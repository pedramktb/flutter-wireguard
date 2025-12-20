#include <windows.h>

#include <codecvt>
#include <stdexcept>
#include <string>

#include "utils.h"

namespace flutter_wireguard
{

  std::wstring WriteConfigToTempFile(std::string name, std::string config)
  {
    WCHAR temp_path[MAX_PATH];
    DWORD temp_path_len = GetTempPath(MAX_PATH, temp_path);
    if (temp_path_len > MAX_PATH || temp_path_len == 0)
    {
      throw std::runtime_error(ErrorWithCode("could not get temporary dir", GetLastError()));
    }

    std::wstring wname = Utf8ToWide(name);
    std::wstring temp_filename = std::wstring(temp_path) + wname + L".conf";

    HANDLE temp_file = CreateFile(temp_filename.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (temp_file == INVALID_HANDLE_VALUE)
    {
      throw std::runtime_error(ErrorWithCode("unable to create temporary file", GetLastError()));
    }

    DWORD bytes_written;
    if (!WriteFile(temp_file, config.c_str(), static_cast<DWORD>(config.length()), &bytes_written, NULL))
    {
      throw std::runtime_error(ErrorWithCode("could not write temporary config file", GetLastError()));
    }

    if (!CloseHandle(temp_file))
    {
      throw std::runtime_error(ErrorWithCode("unable to close temporary file", GetLastError()));
    }
    return temp_filename;
  }

} // namespace flutter_wireguard
