// Linux plugin glue. Bridges Pigeon-generated GObject HostApi vtable to the
// pure-C++ WgBackend, and pushes status events back to Dart via the
// FlutterApi proxy.
#include "include/flutter_wireguard/flutter_wireguard_plugin.h"

#include <flutter_linux/flutter_linux.h>
#include <gtk/gtk.h>

#include <memory>
#include <thread>
#include <utility>
#include <vector>

#include "messages.g.h"
#include "process_runner.h"
#include "wg_backend.h"

#define FLUTTER_WIREGUARD_PLUGIN(obj)                                        \
  (G_TYPE_CHECK_INSTANCE_CAST((obj), flutter_wireguard_plugin_get_type(),    \
                              FlutterWireguardPlugin))

namespace fwg = flutter_wireguard;

struct _FlutterWireguardPlugin {
  GObject parent_instance;
  fwg::WgBackend* backend;                            // owned (raw)
  FlutterWireguardWireguardFlutterApi* flutter_api;   // owned via g_object
  guint poll_timer_id;
  // Set while a background status poll is running; the GLib timer skips
  // the tick instead of queueing another worker, so a slow pkexec call
  // can't cause unbounded thread growth.
  bool poll_in_flight;
};

G_DEFINE_TYPE(FlutterWireguardPlugin, flutter_wireguard_plugin, g_object_get_type())

namespace {

FlutterWireguardTunnelState ToPigeonState(fwg::TunnelStateCpp s) {
  switch (s) {
    case fwg::TunnelStateCpp::kUp:     return FLUTTER_WIREGUARD_TUNNEL_STATE_UP;
    case fwg::TunnelStateCpp::kDown:   return FLUTTER_WIREGUARD_TUNNEL_STATE_DOWN;
    case fwg::TunnelStateCpp::kToggle: return FLUTTER_WIREGUARD_TUNNEL_STATE_TOGGLE;
  }
  return FLUTTER_WIREGUARD_TUNNEL_STATE_DOWN;
}

FlutterWireguardBackendKind ToPigeonBackend(fwg::BackendKindCpp k) {
  switch (k) {
    case fwg::BackendKindCpp::kKernel:    return FLUTTER_WIREGUARD_BACKEND_KIND_KERNEL;
    case fwg::BackendKindCpp::kUserspace: return FLUTTER_WIREGUARD_BACKEND_KIND_USERSPACE;
    case fwg::BackendKindCpp::kUnknown:   return FLUTTER_WIREGUARD_BACKEND_KIND_UNKNOWN;
  }
  return FLUTTER_WIREGUARD_BACKEND_KIND_UNKNOWN;
}

FlutterWireguardTunnelStatus* ToPigeonStatus(const fwg::TunnelStatusCpp& s) {
  return flutter_wireguard_tunnel_status_new(
      s.name.c_str(), ToPigeonState(s.state), s.rx, s.tx, s.handshake);
}

// ---- Async dispatch helpers ----------------------------------------------
//
// HostApi vtable callbacks fire on the GLib main thread. Any blocking work
// (subprocess invocations) must move to a worker thread. We use a small struct
// per call to capture inputs+outputs and bounce the response back via
// g_idle_add so we touch FlBinaryMessenger only from the main thread.

struct StartCtx {
  FlutterWireguardPlugin* plugin;
  FlutterWireguardWireguardHostApiResponseHandle* handle;
  std::string name;
  std::string config;
  std::string error;
  bool ok = false;
};

gboolean StartReply(gpointer data) {
  auto* c = static_cast<StartCtx*>(data);
  if (c->ok) {
    flutter_wireguard_wireguard_host_api_respond_start(c->handle);
  } else {
    flutter_wireguard_wireguard_host_api_respond_error_start(
        c->handle, "START_FAILED", c->error.c_str(), nullptr);
  }
  g_object_unref(c->handle);
  g_object_unref(c->plugin);
  delete c;
  return G_SOURCE_REMOVE;
}

void HandleStart(const gchar* name, const gchar* config,
                 FlutterWireguardWireguardHostApiResponseHandle* handle,
                 gpointer user_data) {
  auto* plugin = FLUTTER_WIREGUARD_PLUGIN(user_data);
  g_object_ref(plugin);
  g_object_ref(handle);
  auto* ctx = new StartCtx{plugin, handle, name, config, "", false};
  std::thread([ctx]() {
    try {
      ctx->plugin->backend->Start(ctx->name, ctx->config);
      ctx->ok = true;
    } catch (const std::exception& e) {
      ctx->error = e.what();
      ctx->ok = false;
    }
    g_idle_add(StartReply, ctx);
  }).detach();
}

struct StopCtx {
  FlutterWireguardPlugin* plugin;
  FlutterWireguardWireguardHostApiResponseHandle* handle;
  std::string name;
  std::string error;
  bool ok = false;
};

gboolean StopReply(gpointer data) {
  auto* c = static_cast<StopCtx*>(data);
  if (c->ok) {
    flutter_wireguard_wireguard_host_api_respond_stop(c->handle);
  } else {
    flutter_wireguard_wireguard_host_api_respond_error_stop(
        c->handle, "STOP_FAILED", c->error.c_str(), nullptr);
  }
  g_object_unref(c->handle);
  g_object_unref(c->plugin);
  delete c;
  return G_SOURCE_REMOVE;
}

void HandleStop(const gchar* name,
                FlutterWireguardWireguardHostApiResponseHandle* handle,
                gpointer user_data) {
  auto* plugin = FLUTTER_WIREGUARD_PLUGIN(user_data);
  g_object_ref(plugin);
  g_object_ref(handle);
  auto* ctx = new StopCtx{plugin, handle, name, "", false};
  std::thread([ctx]() {
    try {
      ctx->plugin->backend->Stop(ctx->name);
      ctx->ok = true;
    } catch (const std::exception& e) {
      ctx->error = e.what();
      ctx->ok = false;
    }
    g_idle_add(StopReply, ctx);
  }).detach();
}

struct StatusCtx {
  FlutterWireguardPlugin* plugin;
  FlutterWireguardWireguardHostApiResponseHandle* handle;
  std::string name;
  fwg::TunnelStatusCpp result;
  std::string error;
  bool ok = false;
};

gboolean StatusReply(gpointer data) {
  auto* c = static_cast<StatusCtx*>(data);
  if (c->ok) {
    FlutterWireguardTunnelStatus* status = ToPigeonStatus(c->result);
    flutter_wireguard_wireguard_host_api_respond_status(c->handle, status);
    g_object_unref(status);
  } else {
    flutter_wireguard_wireguard_host_api_respond_error_status(
        c->handle, "STATUS_FAILED", c->error.c_str(), nullptr);
  }
  g_object_unref(c->handle);
  g_object_unref(c->plugin);
  delete c;
  return G_SOURCE_REMOVE;
}

void HandleStatus(const gchar* name,
                  FlutterWireguardWireguardHostApiResponseHandle* handle,
                  gpointer user_data) {
  auto* plugin = FLUTTER_WIREGUARD_PLUGIN(user_data);
  g_object_ref(plugin);
  g_object_ref(handle);
  auto* ctx = new StatusCtx{plugin, handle, name, {}, "", false};
  std::thread([ctx]() {
    try {
      ctx->result = ctx->plugin->backend->Status(ctx->name);
      ctx->ok = true;
    } catch (const std::exception& e) {
      ctx->error = e.what();
      ctx->ok = false;
    }
    g_idle_add(StatusReply, ctx);
  }).detach();
}

void HandleTunnelNames(FlutterWireguardWireguardHostApiResponseHandle* handle,
                       gpointer user_data) {
  auto* plugin = FLUTTER_WIREGUARD_PLUGIN(user_data);
  auto names = plugin->backend->TunnelNames();
  g_autoptr(FlValue) list = fl_value_new_list();
  for (const auto& n : names) {
    fl_value_append_take(list, fl_value_new_string(n.c_str()));
  }
  flutter_wireguard_wireguard_host_api_respond_tunnel_names(handle, list);
}

void HandleBackend(FlutterWireguardWireguardHostApiResponseHandle* handle,
                   gpointer user_data) {
  auto* plugin = FLUTTER_WIREGUARD_PLUGIN(user_data);
  auto info = plugin->backend->Backend();
  FlutterWireguardBackendInfo* bi = flutter_wireguard_backend_info_new(
      ToPigeonBackend(info.kind), info.detail.c_str());
  flutter_wireguard_wireguard_host_api_respond_backend(handle, bi);
  g_object_unref(bi);
}

const FlutterWireguardWireguardHostApiVTable kVTable = {
    /*start=*/HandleStart,
    /*stop=*/HandleStop,
    /*status=*/HandleStatus,
    /*tunnel_names=*/HandleTunnelNames,
    /*backend=*/HandleBackend,
};

// One-second status poller. The GLib timer fires on the main loop, but the
// actual `Status()` calls reach into PrivilegedSession (blocking I/O on the
// pkexec pipe) so we hand the work to a worker thread and post the per-tunnel
// updates back via g_idle_add. A simple in-flight flag prevents queueing.
struct StatusPollContext {
  FlutterWireguardPlugin* plugin;
  std::vector<std::pair<std::string, fwg::TunnelStatusCpp>> results;
};

gboolean StatusPollDispatch(gpointer user_data) {
  std::unique_ptr<StatusPollContext> ctx(
      static_cast<StatusPollContext*>(user_data));
  auto* self = ctx->plugin;
  if (self->flutter_api != nullptr) {
    for (auto& [_, s] : ctx->results) {
      FlutterWireguardTunnelStatus* status = ToPigeonStatus(s);
      flutter_wireguard_wireguard_flutter_api_on_tunnel_status(
          self->flutter_api, status, nullptr, nullptr, nullptr);
      g_object_unref(status);
    }
  }
  self->poll_in_flight = false;
  g_object_unref(self);
  return G_SOURCE_REMOVE;
}

gboolean StatusPollCallback(gpointer user_data) {
  auto* self = FLUTTER_WIREGUARD_PLUGIN(user_data);
  if (self->backend == nullptr || self->flutter_api == nullptr) {
    return G_SOURCE_CONTINUE;
  }
  if (self->poll_in_flight) {
    // Previous tick still talking to pkexec; don't pile up.
    return G_SOURCE_CONTINUE;
  }
  self->poll_in_flight = true;
  g_object_ref(self);
  std::thread([self] {
    auto* ctx = new StatusPollContext{self, {}};
    for (const auto& name : self->backend->TunnelNames()) {
      try {
        ctx->results.emplace_back(name, self->backend->Status(name));
      } catch (...) {
        // skip this tunnel
      }
    }
    g_idle_add(StatusPollDispatch, ctx);
  }).detach();
  return G_SOURCE_CONTINUE;
}

}  // namespace

static void flutter_wireguard_plugin_dispose(GObject* object) {
  auto* self = FLUTTER_WIREGUARD_PLUGIN(object);
  if (self->poll_timer_id != 0) {
    g_source_remove(self->poll_timer_id);
    self->poll_timer_id = 0;
  }
  g_clear_object(&self->flutter_api);
  delete self->backend;
  self->backend = nullptr;
  G_OBJECT_CLASS(flutter_wireguard_plugin_parent_class)->dispose(object);
}

static void flutter_wireguard_plugin_class_init(FlutterWireguardPluginClass* klass) {
  G_OBJECT_CLASS(klass)->dispose = flutter_wireguard_plugin_dispose;
}

static void flutter_wireguard_plugin_init(FlutterWireguardPlugin* self) {
  self->backend = nullptr;
  self->flutter_api = nullptr;
  self->poll_timer_id = 0;
  self->poll_in_flight = false;
}

void flutter_wireguard_plugin_register_with_registrar(FlPluginRegistrar* registrar) {
  auto* plugin = FLUTTER_WIREGUARD_PLUGIN(
      g_object_new(flutter_wireguard_plugin_get_type(), nullptr));

  auto runner = std::make_unique<fwg::RealProcessRunner>();
  plugin->backend = new fwg::WgBackend(std::move(runner));

  FlBinaryMessenger* messenger = fl_plugin_registrar_get_messenger(registrar);
  // Hand strong ownership of `plugin` to the method handlers; the engine will
  // call g_object_unref via the destroy_notify when the channel is torn down.
  flutter_wireguard_wireguard_host_api_set_method_handlers(
      messenger, /*suffix=*/nullptr, &kVTable, plugin, g_object_unref);
  plugin->flutter_api = flutter_wireguard_wireguard_flutter_api_new(messenger, nullptr);

  plugin->poll_timer_id = g_timeout_add_seconds(1, StatusPollCallback, plugin);
}
