#include <flutter/encodable_value.h>
#include <windows.h>

#include <sstream>
#include <string>

namespace wireguard_flutter
{

  const flutter::EncodableValue *ValueOrNull(const flutter::EncodableMap &map, const char *key)
  {
    auto it = map.find(flutter::EncodableValue(key));
    if (it == map.end())
    {
      return nullptr;
    }
    return &(it->second);
  }

  std::string ErrorWithCode(const char *msg, unsigned long error_code)
  {
    std::ostringstream builder;
    builder << msg << " (" << error_code << ")";
    return builder.str();
  }

  std::string WideToUtf8(const std::wstring &wstr)
  {
    if (wstr.empty())
    {
      return std::string();
    }
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), NULL, 0, NULL, NULL);
    if (size_needed <= 0)
    {
      return std::string();
    }
    std::string strTo(static_cast<size_t>(size_needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), strTo.data(), size_needed, NULL, NULL);
    return strTo;
  }

  std::wstring Utf8ToWide(const std::string &str)
  {
    if (str.empty())
    {
      return std::wstring();
    }
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), NULL, 0);
    if (size_needed <= 0)
    {
      return std::wstring();
    }
    std::wstring wstrTo(static_cast<size_t>(size_needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), wstrTo.data(), size_needed);
    return wstrTo;
  }

  std::string WideToAnsi(const std::wstring &wstr)
  {
    if (wstr.empty())
    {
      return std::string();
    }
    int size_needed = WideCharToMultiByte(CP_ACP, 0, wstr.data(), static_cast<int>(wstr.size()), NULL, 0, NULL, NULL);
    if (size_needed <= 0)
    {
      return std::string();
    }
    std::string strTo(static_cast<size_t>(size_needed), '\0');
    WideCharToMultiByte(CP_ACP, 0, wstr.data(), static_cast<int>(wstr.size()), strTo.data(), size_needed, NULL, NULL);
    return strTo;
  }

  std::wstring AnsiToWide(const std::string &str)
  {
    if (str.empty())
    {
      return std::wstring();
    }
    int size_needed = MultiByteToWideChar(CP_ACP, 0, str.data(), static_cast<int>(str.size()), NULL, 0);
    if (size_needed <= 0)
    {
      return std::wstring();
    }
    std::wstring wstrTo(static_cast<size_t>(size_needed), L'\0');
    MultiByteToWideChar(CP_ACP, 0, str.data(), static_cast<int>(str.size()), wstrTo.data(), size_needed);
    return wstrTo;
  }

  void DebugMessageBox(const char *msg)
  {
    std::string s(msg);
    std::wstring ws = Utf8ToWide(s);
    MessageBox(NULL, ws.c_str(), L"Debug", MB_OK);
  }

} // namespace wireguard_flutter
