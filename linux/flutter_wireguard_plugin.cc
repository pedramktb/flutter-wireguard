#include "include/flutter_wireguard/flutter_wireguard_plugin.h"

#include <flutter_linux/flutter_linux.h>
#include <gtk/gtk.h>
#include <sys/utsname.h>

#include <cstring>
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <memory>
#include <chrono>

#include "flutter_wireguard_plugin_private.h"

#define FLUTTER_WIREGUARD_PLUGIN(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj), flutter_wireguard_plugin_get_type(), \
                              FlutterWireguardPlugin))

struct _FlutterWireguardPlugin {
  GObject parent_instance;
  FlEventChannel* event_channel;
  gchar* tunnel_name;
  guint timer_id;
};

G_DEFINE_TYPE(FlutterWireguardPlugin, flutter_wireguard_plugin, g_object_get_type())

// Helper function to execute shell commands
static std::string exec_command(const char* cmd) {
  std::array<char, 128> buffer;
  std::string result;
  std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
  if (!pipe) {
    return "";
  }
  while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
    result += buffer.data();
  }
  return result;
}

// Helper function to write config file
static bool write_config_file(const gchar* name, const gchar* config) {
  std::string config_path = "/etc/wireguard/";
  config_path += name;
  config_path += ".conf";
  
  std::ofstream config_file(config_path);
  if (!config_file.is_open()) {
    return false;
  }
  
  config_file << config;
  config_file.close();
  
  // Set permissions to 600
  std::string chmod_cmd = "chmod 600 " + config_path;
  system(chmod_cmd.c_str());
  
  return true;
}

// Helper function to get handshake timestamp in milliseconds
static int64_t get_handshake_timestamp(const gchar* name) {
  std::string cmd = "wg show ";
  cmd += name;
  cmd += " latest-handshakes 2>/dev/null";
  
  std::string output = exec_command(cmd.c_str());
  
  if (output.empty()) {
    return 0;
  }
  
  // Parse the output - format: <public_key>\t<timestamp_seconds>
  size_t tab_pos = output.find('\t');
  if (tab_pos == std::string::npos) {
    return 0;
  }
  
  std::string timestamp_str = output.substr(tab_pos + 1);
  try {
    int64_t timestamp_sec = std::stoll(timestamp_str);
    // Convert to milliseconds
    return timestamp_sec * 1000;
  } catch (...) {
    return 0;
  }
}

// Helper function to get transfer statistics
static void get_transfer_stats(const gchar* name, int64_t* rx, int64_t* tx) {
  std::string cmd = "wg show ";
  cmd += name;
  cmd += " transfer 2>/dev/null";
  
  std::string output = exec_command(cmd.c_str());
  
  if (output.empty()) {
    *rx = 0;
    *tx = 0;
    return;
  }
  
  // Parse the output - format: <public_key>\t<rx_bytes>\t<tx_bytes>
  std::istringstream iss(output);
  std::string public_key, rx_str, tx_str;
  
  if (std::getline(iss, public_key, '\t') &&
      std::getline(iss, rx_str, '\t') &&
      std::getline(iss, tx_str)) {
    try {
      *rx = std::stoll(rx_str);
      *tx = std::stoll(tx_str);
    } catch (...) {
      *rx = 0;
      *tx = 0;
    }
  } else {
    *rx = 0;
    *tx = 0;
  }
}

// Helper function to check if interface exists and is up
static bool is_interface_up(const gchar* name) {
  std::string cmd = "ip link show ";
  cmd += name;
  cmd += " 2>/dev/null | grep -q 'state UP'";
  
  int result = system(cmd.c_str());
  return result == 0;
}

// Called when a method call is received from Flutter.
static void flutter_wireguard_plugin_handle_method_call(
    FlutterWireguardPlugin* self,
    FlMethodCall* method_call) {
  g_autoptr(FlMethodResponse) response = nullptr;

  const gchar* method = fl_method_call_get_name(method_call);

  if (strcmp(method, "start") == 0) {
    FlValue* args = fl_method_call_get_args(method_call);
    FlValue* name_value = fl_value_lookup_string(args, "name");
    FlValue* config_value = fl_value_lookup_string(args, "config");
    
    if (name_value == nullptr || config_value == nullptr) {
      response = FL_METHOD_RESPONSE(fl_method_error_response_new(
          "INVALID_ARGS", "Missing name or config argument", nullptr));
    } else {
      const gchar* name = fl_value_get_string(name_value);
      const gchar* config = fl_value_get_string(config_value);
      
      // Store tunnel name
      if (self->tunnel_name) {
        g_free(self->tunnel_name);
      }
      self->tunnel_name = g_strdup(name);
      
      // Write config file
      if (!write_config_file(name, config)) {
        response = FL_METHOD_RESPONSE(fl_method_error_response_new(
            "CONFIG_ERROR", "Failed to write config file", nullptr));
      } else {
        // Start WireGuard interface
        std::string start_cmd = "wg-quick up ";
        start_cmd += name;
        start_cmd += " 2>&1";
        
        std::string result = exec_command(start_cmd.c_str());
        
        if (is_interface_up(name)) {
          response = FL_METHOD_RESPONSE(fl_method_success_response_new(nullptr));
        } else {
          g_autofree gchar* error_msg = g_strdup_printf("Failed to start tunnel: %s", result.c_str());
          response = FL_METHOD_RESPONSE(fl_method_error_response_new(
              "START_ERROR", error_msg, nullptr));
        }
      }
    }
  } else if (strcmp(method, "stop") == 0) {
    FlValue* args = fl_method_call_get_args(method_call);
    FlValue* name_value = fl_value_lookup_string(args, "name");
    
    if (name_value == nullptr) {
      response = FL_METHOD_RESPONSE(fl_method_error_response_new(
          "INVALID_ARGS", "Missing name argument", nullptr));
    } else {
      const gchar* name = fl_value_get_string(name_value);
      
      // Stop WireGuard interface
      std::string stop_cmd = "wg-quick down ";
      stop_cmd += name;
      stop_cmd += " 2>&1";
      
      exec_command(stop_cmd.c_str());
      response = FL_METHOD_RESPONSE(fl_method_success_response_new(nullptr));
    }
  } else if (strcmp(method, "status") == 0) {
    FlValue* args = fl_method_call_get_args(method_call);
    FlValue* name_value = fl_value_lookup_string(args, "name");
    
    if (name_value == nullptr) {
      response = FL_METHOD_RESPONSE(fl_method_error_response_new(
          "INVALID_ARGS", "Missing name argument", nullptr));
    } else {
      const gchar* name = fl_value_get_string(name_value);
      
      bool is_up = is_interface_up(name);
      int64_t rx = 0, tx = 0;
      int64_t handshake = get_handshake_timestamp(name);
      
      if (is_up) {
        get_transfer_stats(name, &rx, &tx);
      }
      
      g_autoptr(FlValue) result_map = fl_value_new_map();
      fl_value_set_string_take(result_map, "name", fl_value_new_string(name));
      fl_value_set_string_take(result_map, "state", fl_value_new_string(is_up ? "UP" : "DOWN"));
      fl_value_set_string_take(result_map, "rx", fl_value_new_int(rx));
      fl_value_set_string_take(result_map, "tx", fl_value_new_int(tx));
      fl_value_set_string_take(result_map, "handshake", fl_value_new_int(handshake));
      
      response = FL_METHOD_RESPONSE(fl_method_success_response_new(result_map));
    }
  } else {
    response = FL_METHOD_RESPONSE(fl_method_not_implemented_response_new());
  }

  fl_method_call_respond(method_call, response, nullptr);
}

FlMethodResponse* get_platform_version() {
  struct utsname uname_data = {};
  uname(&uname_data);
  g_autofree gchar *version = g_strdup_printf("Linux %s", uname_data.version);
  g_autoptr(FlValue) result = fl_value_new_string(version);
  return FL_METHOD_RESPONSE(fl_method_success_response_new(result));
}

// Event channel timer callback
static gboolean status_timer_callback(gpointer user_data) {
  FlutterWireguardPlugin* self = FLUTTER_WIREGUARD_PLUGIN(user_data);
  
  if (self->tunnel_name == nullptr) {
    return G_SOURCE_CONTINUE;
  }
  
  bool is_up = is_interface_up(self->tunnel_name);
  int64_t rx = 0, tx = 0;
  int64_t handshake = get_handshake_timestamp(self->tunnel_name);
  
  if (is_up) {
    get_transfer_stats(self->tunnel_name, &rx, &tx);
  }
  
  g_autoptr(FlValue) event_map = fl_value_new_map();
  fl_value_set_string_take(event_map, "name", fl_value_new_string(self->tunnel_name));
  fl_value_set_string_take(event_map, "state", fl_value_new_string(is_up ? "UP" : "DOWN"));
  fl_value_set_string_take(event_map, "rx", fl_value_new_int(rx));
  fl_value_set_string_take(event_map, "tx", fl_value_new_int(tx));
  fl_value_set_string_take(event_map, "handshake", fl_value_new_int(handshake));
  
  fl_event_channel_send(self->event_channel, event_map, nullptr, nullptr);
  
  return G_SOURCE_CONTINUE;
}

// Event channel listen handler
static FlMethodErrorResponse* event_listen_cb(
    FlEventChannel* channel,
    FlValue* args,
    gpointer user_data) {
  FlutterWireguardPlugin* self = FLUTTER_WIREGUARD_PLUGIN(user_data);
  
  // Start timer to emit status updates every second
  if (self->timer_id == 0) {
    self->timer_id = g_timeout_add_seconds(1, status_timer_callback, self);
  }
  
  return nullptr;
}

// Event channel cancel handler
static FlMethodErrorResponse* event_cancel_cb(
    FlEventChannel* channel,
    FlValue* args,
    gpointer user_data) {
  FlutterWireguardPlugin* self = FLUTTER_WIREGUARD_PLUGIN(user_data);
  
  // Stop timer
  if (self->timer_id != 0) {
    g_source_remove(self->timer_id);
    self->timer_id = 0;
  }
  
  return nullptr;
}

static void flutter_wireguard_plugin_dispose(GObject* object) {
  FlutterWireguardPlugin* self = FLUTTER_WIREGUARD_PLUGIN(object);
  
  if (self->timer_id != 0) {
    g_source_remove(self->timer_id);
    self->timer_id = 0;
  }
  
  if (self->tunnel_name) {
    g_free(self->tunnel_name);
    self->tunnel_name = nullptr;
  }
  
  G_OBJECT_CLASS(flutter_wireguard_plugin_parent_class)->dispose(object);
}

static void flutter_wireguard_plugin_class_init(FlutterWireguardPluginClass* klass) {
  G_OBJECT_CLASS(klass)->dispose = flutter_wireguard_plugin_dispose;
}

static void flutter_wireguard_plugin_init(FlutterWireguardPlugin* self) {
  self->tunnel_name = nullptr;
  self->timer_id = 0;
}

static void method_call_cb(FlMethodChannel* channel, FlMethodCall* method_call,
                           gpointer user_data) {
  FlutterWireguardPlugin* plugin = FLUTTER_WIREGUARD_PLUGIN(user_data);
  flutter_wireguard_plugin_handle_method_call(plugin, method_call);
}

void flutter_wireguard_plugin_register_with_registrar(FlPluginRegistrar* registrar) {
  FlutterWireguardPlugin* plugin = FLUTTER_WIREGUARD_PLUGIN(
      g_object_new(flutter_wireguard_plugin_get_type(), nullptr));

  g_autoptr(FlStandardMethodCodec) codec = fl_standard_method_codec_new();
  
  // Register method channel
  g_autoptr(FlMethodChannel) method_channel =
      fl_method_channel_new(fl_plugin_registrar_get_messenger(registrar),
                            "dev.fluttercommunity.flutter_wireguard/methodChannel",
                            FL_METHOD_CODEC(codec));
  fl_method_channel_set_method_call_handler(method_channel, method_call_cb,
                                            g_object_ref(plugin),
                                            g_object_unref);
  
  // Register event channel
  g_autoptr(FlStandardMethodCodec) event_codec = fl_standard_method_codec_new();
  plugin->event_channel =
      fl_event_channel_new(fl_plugin_registrar_get_messenger(registrar),
                          "dev.fluttercommunity.flutter_wireguard/eventChannel",
                          FL_METHOD_CODEC(event_codec));
  fl_event_channel_set_stream_handlers(plugin->event_channel,
                                       event_listen_cb,
                                       event_cancel_cb,
                                       g_object_ref(plugin),
                                       g_object_unref);

  g_object_unref(plugin);
}
