#include "utils.h"

#include <windows.h>

#include <sstream>

namespace flutter_wireguard {

std::string ErrorWithCode(const char* msg, unsigned long error_code) {
  std::ostringstream out;
  out << msg << " (" << error_code;
  LPSTR sys_msg = nullptr;
  DWORD len = ::FormatMessageA(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
          FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      reinterpret_cast<LPSTR>(&sys_msg), 0, nullptr);
  if (len > 0 && sys_msg != nullptr) {
    // Strip trailing CR/LF.
    while (len > 0 && (sys_msg[len - 1] == '\r' || sys_msg[len - 1] == '\n' ||
                       sys_msg[len - 1] == ' ')) {
      sys_msg[--len] = '\0';
    }
    out << ": " << sys_msg;
  }
  if (sys_msg != nullptr) ::LocalFree(sys_msg);
  out << ")";
  return out.str();
}

std::string WideToUtf8(const std::wstring& wstr) {
  if (wstr.empty()) return {};
  int needed = ::WideCharToMultiByte(CP_UTF8, 0, wstr.data(),
                                     static_cast<int>(wstr.size()), nullptr, 0,
                                     nullptr, nullptr);
  if (needed <= 0) return {};
  std::string out(static_cast<size_t>(needed), '\0');
  ::WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()),
                        out.data(), needed, nullptr, nullptr);
  return out;
}

std::wstring Utf8ToWide(const std::string& str) {
  if (str.empty()) return {};
  int needed = ::MultiByteToWideChar(CP_UTF8, 0, str.data(),
                                     static_cast<int>(str.size()), nullptr, 0);
  if (needed <= 0) return {};
  std::wstring out(static_cast<size_t>(needed), L'\0');
  ::MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()),
                        out.data(), needed);
  return out;
}

void Log(const std::string& message) {
  std::string msg = message + "\n";
  ::OutputDebugStringA(msg.c_str());
}

void Log(const std::wstring& message) {
  std::wstring msg = message + L"\n";
  ::OutputDebugStringW(msg.c_str());
}

}  // namespace flutter_wireguard
