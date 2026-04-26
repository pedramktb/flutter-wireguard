// Win32 / std utility helpers shared between the Flutter plugin DLL and the
// elevated helper.exe broker. No Flutter / Pigeon dependencies on purpose:
// helper.exe must not link against the Flutter Windows engine.
#ifndef FLUTTER_WIREGUARD_UTILS_H_
#define FLUTTER_WIREGUARD_UTILS_H_

#include <windows.h>

#include <string>

namespace flutter_wireguard {

// "<msg> (<code>: <FormatMessageA>)" — the trailing system-message piece is
// best-effort; on failure only the code is appended.
std::string ErrorWithCode(const char* msg, unsigned long error_code);

// UTF-8 <-> UTF-16 conversions. Centralised so every boundary is auditable.
std::string WideToUtf8(const std::wstring& wstr);
std::wstring Utf8ToWide(const std::string& str);

// Best-effort logging via OutputDebugString. Never logs config payloads.
void Log(const std::string& message);
void Log(const std::wstring& message);

}  // namespace flutter_wireguard

#endif  // FLUTTER_WIREGUARD_UTILS_H_
