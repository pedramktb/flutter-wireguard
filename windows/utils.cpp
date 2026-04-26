#include "utils.h"

#include <windows.h>

#include <cstdio>
#include <mutex>
#include <sstream>

namespace flutter_wireguard {

namespace {

// Tee logs to %TEMP%\flutter_wireguard.log so they survive even when
// OutputDebugString isn't being captured by a debugger.
void AppendLogFile(const std::string& utf8) {
  static std::mutex mu;
  std::lock_guard<std::mutex> lock(mu);
  wchar_t temp[MAX_PATH];
  DWORD n = ::GetTempPathW(MAX_PATH, temp);
  if (n == 0 || n >= MAX_PATH) return;
  std::wstring path = std::wstring(temp, n) + L"flutter_wireguard.log";
  HANDLE h = ::CreateFileW(path.c_str(), FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) return;
  SYSTEMTIME st;
  ::GetLocalTime(&st);
  char prefix[64];
  int pn = std::snprintf(prefix, sizeof(prefix),
                         "[%04u-%02u-%02u %02u:%02u:%02u.%03u pid=%lu] ",
                         st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
                         st.wSecond, st.wMilliseconds,
                         ::GetCurrentProcessId());
  DWORD wrote = 0;
  if (pn > 0) ::WriteFile(h, prefix, pn, &wrote, nullptr);
  ::WriteFile(h, utf8.data(), static_cast<DWORD>(utf8.size()), &wrote, nullptr);
  ::WriteFile(h, "\n", 1, &wrote, nullptr);
  ::CloseHandle(h);
}

}  // namespace

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
  AppendLogFile(message);
}

void Log(const std::wstring& message) {
  std::wstring msg = message + L"\n";
  ::OutputDebugStringW(msg.c_str());
  AppendLogFile(WideToUtf8(message));
}

}  // namespace flutter_wireguard
