#include "config_writer.h"

#include <aclapi.h>
#include <dpapi.h>
#include <shlobj.h>
#include <windows.h>

#include <stdexcept>
#include <vector>

#include "../utils.h"

namespace flutter_wireguard {

namespace {

std::wstring ProgramDataPath() {
  PWSTR raw = nullptr;
  HRESULT hr = ::SHGetKnownFolderPath(FOLDERID_ProgramData, 0, nullptr, &raw);
  if (FAILED(hr) || raw == nullptr) {
    if (raw != nullptr) ::CoTaskMemFree(raw);
    throw std::runtime_error("SHGetKnownFolderPath(ProgramData) failed");
  }
  std::wstring out(raw);
  ::CoTaskMemFree(raw);
  return out;
}

// Builds an ACL granting full control only to LocalSystem and Administrators.
// Owner is set to Administrators. No inheritance.
void ApplyRestrictiveDacl(const std::wstring& path) {
  PSID admins = nullptr, system = nullptr;
  SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
  if (!::AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                  &admins) ||
      !::AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0,
                                  0, 0, 0, 0, &system)) {
    if (admins != nullptr) ::FreeSid(admins);
    if (system != nullptr) ::FreeSid(system);
    throw std::runtime_error(
        ErrorWithCode("AllocateAndInitializeSid", ::GetLastError()));
  }

  EXPLICIT_ACCESS_W ea[2] = {};
  ea[0].grfAccessPermissions = GENERIC_ALL;
  ea[0].grfAccessMode = SET_ACCESS;
  ea[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
  ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
  ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
  ea[0].Trustee.ptstrName = reinterpret_cast<LPWSTR>(admins);
  ea[1] = ea[0];
  ea[1].Trustee.ptstrName = reinterpret_cast<LPWSTR>(system);

  PACL acl = nullptr;
  DWORD err = ::SetEntriesInAclW(2, ea, nullptr, &acl);
  if (err != ERROR_SUCCESS) {
    ::FreeSid(admins);
    ::FreeSid(system);
    throw std::runtime_error(ErrorWithCode("SetEntriesInAcl", err));
  }

  err = ::SetNamedSecurityInfoW(
      const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
      DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION |
          OWNER_SECURITY_INFORMATION,
      admins, nullptr, acl, nullptr);
  if (acl != nullptr) ::LocalFree(acl);
  ::FreeSid(admins);
  ::FreeSid(system);
  if (err != ERROR_SUCCESS) {
    throw std::runtime_error(ErrorWithCode("SetNamedSecurityInfo", err));
  }
}

std::wstring ConfDir() {
  std::wstring base = ProgramDataPath() + L"\\flutter_wireguard\\configs";
  // Create both ancestors. CreateDirectoryW returns FALSE+ALREADY_EXISTS on
  // the second call, which is fine.
  std::wstring parent = ProgramDataPath() + L"\\flutter_wireguard";
  ::CreateDirectoryW(parent.c_str(), nullptr);
  if (::CreateDirectoryW(base.c_str(), nullptr)) {
    ApplyRestrictiveDacl(base);
  }
  return base;
}

void WriteAllBytes(const std::wstring& path, const void* data, size_t len) {
  HANDLE h = ::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                           nullptr);
  if (h == INVALID_HANDLE_VALUE) {
    throw std::runtime_error(
        ErrorWithCode("CreateFile(config)", ::GetLastError()));
  }
  const BYTE* p = static_cast<const BYTE*>(data);
  size_t left = len;
  while (left > 0) {
    DWORD chunk =
        static_cast<DWORD>(left > 0x10000 ? 0x10000 : left);
    DWORD written = 0;
    if (!::WriteFile(h, p, chunk, &written, nullptr) || written == 0) {
      DWORD err = ::GetLastError();
      ::CloseHandle(h);
      throw std::runtime_error(ErrorWithCode("WriteFile(config)", err));
    }
    p += written;
    left -= written;
  }
  ::CloseHandle(h);
}

}  // namespace

std::wstring SecureConfigStore::EnsureDir() { return ConfDir(); }

std::wstring SecureConfigStore::WriteEncrypted(const std::wstring& name,
                                               const std::string& config) {
  std::wstring path = ConfDir() + L"\\" + name + L".conf.dpapi";

  DATA_BLOB in{};
  in.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(config.data()));
  in.cbData = static_cast<DWORD>(config.size());
  DATA_BLOB out{};
  // Use LOCAL_MACHINE so the protected blob is decryptable by SYSTEM (the
  // service account that runs tunnel.dll). CRYPTPROTECT_AUDIT logs decrypts.
  if (!::CryptProtectData(&in, L"flutter_wireguard", nullptr, nullptr, nullptr,
                          CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_AUDIT,
                          &out)) {
    throw std::runtime_error(
        ErrorWithCode("CryptProtectData", ::GetLastError()));
  }
  try {
    WriteAllBytes(path, out.pbData, out.cbData);
  } catch (...) {
    ::LocalFree(out.pbData);
    throw;
  }
  ::LocalFree(out.pbData);
  return path;
}

std::string SecureConfigStore::ReadEncrypted(const std::wstring& name) {
  std::wstring path = ConfDir() + L"\\" + name + L".conf.dpapi";
  HANDLE h = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                           nullptr);
  if (h == INVALID_HANDLE_VALUE) {
    throw std::runtime_error(
        ErrorWithCode("CreateFile(read dpapi)", ::GetLastError()));
  }
  LARGE_INTEGER size{};
  if (!::GetFileSizeEx(h, &size) || size.QuadPart > 0x40000) {
    ::CloseHandle(h);
    throw std::runtime_error("config file too large or unreadable");
  }
  std::vector<BYTE> blob(static_cast<size_t>(size.QuadPart));
  DWORD got = 0;
  if (!::ReadFile(h, blob.data(), static_cast<DWORD>(blob.size()), &got,
                  nullptr) ||
      got != blob.size()) {
    DWORD err = ::GetLastError();
    ::CloseHandle(h);
    throw std::runtime_error(ErrorWithCode("ReadFile(dpapi)", err));
  }
  ::CloseHandle(h);

  DATA_BLOB in{blob.size() ? static_cast<DWORD>(blob.size()) : 0,
               blob.data()};
  DATA_BLOB out{};
  if (!::CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr,
                            CRYPTPROTECT_LOCAL_MACHINE, &out)) {
    throw std::runtime_error(
        ErrorWithCode("CryptUnprotectData", ::GetLastError()));
  }
  std::string plain(reinterpret_cast<char*>(out.pbData), out.cbData);
  // Best-effort wipe before LocalFree.
  ::SecureZeroMemory(out.pbData, out.cbData);
  ::LocalFree(out.pbData);
  return plain;
}

std::wstring SecureConfigStore::WritePlaintext(const std::wstring& name,
                                               const std::string& config) {
  std::wstring path = ConfDir() + L"\\" + name + L".conf";
  WriteAllBytes(path, config.data(), config.size());
  return path;
}

void SecureConfigStore::Erase(const std::wstring& name) {
  std::wstring base = ConfDir() + L"\\" + name;
  std::wstring conf = base + L".conf";
  std::wstring dpapi = base + L".conf.dpapi";

  // Best-effort overwrite: open .conf for write, fill with zeros to its size.
  HANDLE h = ::CreateFileW(conf.c_str(), GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h != INVALID_HANDLE_VALUE) {
    LARGE_INTEGER size{};
    if (::GetFileSizeEx(h, &size) && size.QuadPart > 0 &&
        size.QuadPart < 0x40000) {
      std::vector<BYTE> zeros(static_cast<size_t>(size.QuadPart), 0);
      DWORD wrote = 0;
      ::WriteFile(h, zeros.data(), static_cast<DWORD>(zeros.size()), &wrote,
                  nullptr);
      ::FlushFileBuffers(h);
    }
    ::CloseHandle(h);
  }
  ::DeleteFileW(conf.c_str());
  ::DeleteFileW(dpapi.c_str());
}

}  // namespace flutter_wireguard
