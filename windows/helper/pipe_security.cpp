#include "pipe_security.h"

#include <wtsapi32.h>

#include <vector>

#include "../utils.h"

namespace flutter_wireguard {

namespace {

constexpr DWORD kPipeAccess = FILE_GENERIC_READ | FILE_GENERIC_WRITE;

}  // namespace

std::unique_ptr<PipeSecurity> PipeSecurity::Create(PSID client_user_sid) {
  if (client_user_sid == nullptr) return nullptr;

  std::unique_ptr<PipeSecurity> ps(new PipeSecurity());

  // BUILTIN\Administrators
  SID_IDENTIFIER_AUTHORITY nt_auth = SECURITY_NT_AUTHORITY;
  if (!::AllocateAndInitializeSid(&nt_auth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                  &ps->admins_sid_)) {
    Log(ErrorWithCode("AllocateAndInitializeSid(admins)", ::GetLastError()));
    return nullptr;
  }
  // NT AUTHORITY\SYSTEM
  if (!::AllocateAndInitializeSid(&nt_auth, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0,
                                  0, 0, 0, 0, 0, &ps->system_sid_)) {
    Log(ErrorWithCode("AllocateAndInitializeSid(system)", ::GetLastError()));
    return nullptr;
  }

  EXPLICIT_ACCESS_W ea[3] = {};
  for (int i = 0; i < 3; ++i) {
    ea[i].grfAccessPermissions = kPipeAccess;
    ea[i].grfAccessMode = SET_ACCESS;
    ea[i].grfInheritance = NO_INHERITANCE;
    ea[i].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[i].Trustee.TrusteeType = TRUSTEE_IS_USER;
  }
  ea[0].Trustee.ptstrName = reinterpret_cast<LPWSTR>(client_user_sid);
  ea[1].Trustee.ptstrName = reinterpret_cast<LPWSTR>(ps->admins_sid_);
  ea[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
  ea[2].Trustee.ptstrName = reinterpret_cast<LPWSTR>(ps->system_sid_);
  ea[2].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;

  DWORD err = ::SetEntriesInAclW(3, ea, nullptr, &ps->acl_);
  if (err != ERROR_SUCCESS) {
    Log(ErrorWithCode("SetEntriesInAcl", err));
    return nullptr;
  }

  ps->sd_ = static_cast<PSECURITY_DESCRIPTOR>(
      ::LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH));
  if (ps->sd_ == nullptr) return nullptr;
  if (!::InitializeSecurityDescriptor(ps->sd_, SECURITY_DESCRIPTOR_REVISION)) {
    return nullptr;
  }
  if (!::SetSecurityDescriptorDacl(ps->sd_, TRUE, ps->acl_, FALSE)) {
    return nullptr;
  }

  ps->sa_.nLength = sizeof(ps->sa_);
  ps->sa_.lpSecurityDescriptor = ps->sd_;
  ps->sa_.bInheritHandle = FALSE;
  return ps;
}

PipeSecurity::~PipeSecurity() {
  if (acl_ != nullptr) ::LocalFree(acl_);
  if (sd_ != nullptr) ::LocalFree(sd_);
  if (admins_sid_ != nullptr) ::FreeSid(admins_sid_);
  if (system_sid_ != nullptr) ::FreeSid(system_sid_);
}

PSID GetActiveConsoleUserSid() {
  DWORD session_id = ::WTSGetActiveConsoleSessionId();
  if (session_id == 0xFFFFFFFF) return nullptr;
  HANDLE token = nullptr;
  if (!::WTSQueryUserToken(session_id, &token)) {
    Log(ErrorWithCode("WTSQueryUserToken", ::GetLastError()));
    return nullptr;
  }
  DWORD needed = 0;
  ::GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
  if (needed == 0) {
    ::CloseHandle(token);
    return nullptr;
  }
  std::vector<BYTE> buf(needed);
  if (!::GetTokenInformation(token, TokenUser, buf.data(), needed, &needed)) {
    ::CloseHandle(token);
    return nullptr;
  }
  ::CloseHandle(token);
  PSID src = reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid;
  DWORD sid_len = ::GetLengthSid(src);
  PSID copy = ::LocalAlloc(LPTR, sid_len);
  if (copy == nullptr) return nullptr;
  if (!::CopySid(sid_len, copy, src)) {
    ::LocalFree(copy);
    return nullptr;
  }
  return copy;
}

}  // namespace flutter_wireguard
