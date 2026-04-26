#ifndef FLUTTER_WIREGUARD_HELPER_CONFIG_WRITER_H_
#define FLUTTER_WIREGUARD_HELPER_CONFIG_WRITER_H_

#include <windows.h>

#include <string>

namespace flutter_wireguard {

// Where the broker stashes per-tunnel encrypted configs.
//   %PROGRAMDATA%\flutter_wireguard\configs\<name>.conf.dpapi
//
// The directory's DACL is set to grant full control only to LocalSystem and
// BUILTIN\Administrators. The plaintext .conf file written for tunnel.dll's
// consumption (it can't read DPAPI blobs itself) lives next to it with the
// same DACL and is unlinked on Stop.
class SecureConfigStore {
 public:
  // Returns "%PROGRAMDATA%\\flutter_wireguard\\configs", creating it with a
  // restrictive DACL on first call. Throws std::runtime_error on failure.
  static std::wstring EnsureDir();

  // DPAPI-encrypts `config` (LocalMachine scope) and writes it to
  // <dir>\<name>.conf.dpapi. The caller is responsible for name validation.
  static std::wstring WriteEncrypted(const std::wstring& name,
                                     const std::string& config);

  // Reads <dir>\<name>.conf.dpapi and decrypts it to UTF-8. Throws on error.
  static std::string ReadEncrypted(const std::wstring& name);

  // Writes the plaintext form for tunnel.dll's consumption next to the .dpapi
  // blob. The plaintext file inherits the dir DACL (admins/system only) and is
  // shredded by ErasePlaintext on Stop.
  static std::wstring WritePlaintext(const std::wstring& name,
                                     const std::string& config);

  // Best-effort: overwrites the plaintext bytes with zeros, then deletes both
  // the .conf and the .conf.dpapi for the named tunnel.
  static void Erase(const std::wstring& name);
};

}  // namespace flutter_wireguard

#endif  // FLUTTER_WIREGUARD_HELPER_CONFIG_WRITER_H_
