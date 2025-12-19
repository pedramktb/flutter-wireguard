#include <windows.h>

#include <codecvt>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "utils.h"

namespace wireguard_flutter
{

  namespace
  {
    static inline std::string Trim(std::string s)
    {
      const char *ws = " \t\r\n";
      const auto start = s.find_first_not_of(ws);
      if (start == std::string::npos)
      {
        return std::string();
      }
      const auto end = s.find_last_not_of(ws);
      return s.substr(start, end - start + 1);
    }

    static inline bool IStartsWith(const std::string &s, const std::string &prefix)
    {
      if (s.size() < prefix.size())
      {
        return false;
      }
      for (size_t i = 0; i < prefix.size(); ++i)
      {
        char a = s[i];
        char b = prefix[i];
        if (a >= 'A' && a <= 'Z')
          a = static_cast<char>(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z')
          b = static_cast<char>(b - 'A' + 'a');
        if (a != b)
          return false;
      }
      return true;
    }

    // On Windows, configs commonly require CIDR notation (e.g. 10.0.0.2/32).
    // Many mobile-focused configs omit it; normalize safely for common cases.
    static std::string NormalizeConfigForWindows(const std::string &config)
    {
      std::istringstream in(config);
      std::string line;

      bool in_interface = false;
      std::ostringstream out;

      while (std::getline(in, line))
      {
        // Drop any '\r' from CRLF inputs; we re-add CRLF below.
        if (!line.empty() && line.back() == '\r')
        {
          line.pop_back();
        }

        const std::string trimmed = Trim(line);
        if (trimmed.empty() || trimmed[0] == '#' || trimmed[0] == ';')
        {
          out << line << "\r\n";
          continue;
        }

        if (trimmed.size() >= 2 && trimmed.front() == '[' && trimmed.back() == ']')
        {
          in_interface = (trimmed == "[Interface]" || trimmed == "[interface]");
          out << line << "\r\n";
          continue;
        }

        if (in_interface)
        {
          // Only touch Address= lines inside [Interface].
          // Preserve the key portion (including original spacing up to '=').
          auto eq = line.find('=');
          if (eq != std::string::npos)
          {
            std::string key = Trim(line.substr(0, eq));
            if (IStartsWith(key, "address"))
            {
              std::string value = Trim(line.substr(eq + 1));
              std::vector<std::string> parts;

              // Split by comma
              size_t start = 0;
              while (start < value.size())
              {
                size_t comma = value.find(',', start);
                std::string part = (comma == std::string::npos) ? value.substr(start) : value.substr(start, comma - start);
                parts.push_back(Trim(part));
                if (comma == std::string::npos)
                  break;
                start = comma + 1;
              }

              for (auto &addr : parts)
              {
                if (addr.empty())
                  continue;
                if (addr.find('/') != std::string::npos)
                  continue;
                // Heuristic: IPv6 contains ':', IPv4 contains '.'
                if (addr.find(':') != std::string::npos)
                {
                  addr.append("/128");
                }
                else if (addr.find('.') != std::string::npos)
                {
                  addr.append("/32");
                }
              }

              std::ostringstream rebuilt;
              for (size_t i = 0; i < parts.size(); ++i)
              {
                if (i != 0)
                  rebuilt << ", ";
                rebuilt << parts[i];
              }

              out << line.substr(0, eq + 1) << " " << rebuilt.str() << "\r\n";
              continue;
            }
          }
        }

        out << line << "\r\n";
      }

      // Ensure trailing newline
      return out.str();
    }
  } // namespace

  std::wstring WriteConfigToTempFile(std::string config)
  {
    WCHAR temp_path[MAX_PATH];
    DWORD temp_path_len = GetTempPath(MAX_PATH, temp_path);
    if (temp_path_len > MAX_PATH || temp_path_len == 0)
    {
      throw std::runtime_error(ErrorWithCode("could not get temporary dir", GetLastError()));
    }

    WCHAR temp_filename[MAX_PATH];
    UINT temp_filename_result = GetTempFileName(temp_path, L"wg_conf", 0, temp_filename);
    wcscat_s(temp_filename, L".conf");
    if (temp_filename_result == 0)
    {
      throw std::runtime_error(ErrorWithCode("could not get temporary file name", GetLastError()));
    }

    HANDLE temp_file = CreateFile(temp_filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (temp_file == INVALID_HANDLE_VALUE)
    {
      throw std::runtime_error(ErrorWithCode("unable to create temporary file", GetLastError()));
    }

    // Normalize config for Windows compatibility.
    const std::string normalized = NormalizeConfigForWindows(config);

    DWORD bytes_written;
    if (!WriteFile(temp_file, normalized.c_str(), static_cast<DWORD>(normalized.length()), &bytes_written, NULL))
    {
      throw std::runtime_error(ErrorWithCode("could not write temporary config file", GetLastError()));
    }

    if (!CloseHandle(temp_file))
    {
      throw std::runtime_error(ErrorWithCode("unable to close temporary file", GetLastError()));
    }
    return temp_filename;
  }

}
