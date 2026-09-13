#include "subconv/fsutil.hpp"

#include <cstdlib>

#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <sys/stat.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace subconv::fs {
namespace {

bool is_sep(char c) { return c == '/' || c == '\\'; }

int make_one(const std::string& path) {
#ifdef _WIN32
  return _mkdir(path.c_str());
#else
  return mkdir(path.c_str(), 0755);
#endif
}

}  // namespace

bool exists(const std::string& path) {
  if (path.empty()) return false;
#ifdef _WIN32
  return _access(path.c_str(), 0) == 0;
#else
  return access(path.c_str(), F_OK) == 0;
#endif
}

bool is_directory(const std::string& path) {
  if (path.empty()) return false;
#ifdef _WIN32
  struct _stat info {};
  if (_stat(path.c_str(), &info) != 0) return false;
  return (info.st_mode & _S_IFDIR) != 0;
#else
  struct stat info {};
  if (stat(path.c_str(), &info) != 0) return false;
  return S_ISDIR(info.st_mode);
#endif
}

bool make_directories(const std::string& path) {
  if (path.empty()) return false;
  if (is_directory(path)) return true;

  std::string current;
  std::size_t i = 0;
  if (path.size() >= 2 && path[1] == ':') {
    current.assign(path, 0, 2);   // 盘符，如 "C:"
    i = 2;
  } else if (is_sep(path[0])) {
    current = "/";
    i = 1;
  }

  while (i < path.size()) {
    while (i < path.size() && is_sep(path[i])) ++i;
    const std::size_t start = i;
    while (i < path.size() && !is_sep(path[i])) ++i;
    if (i == start) break;

    if (!current.empty() && current.back() != '/') current.push_back('/');
    current.append(path, start, i - start);

    if (!exists(current)) {
      if (make_one(current) != 0 && !is_directory(current)) return false;
    }
  }
  return is_directory(path);
}

std::string join(const std::string& dir, const std::string& name) {
  if (dir.empty()) return name;
  std::string out = dir;
  if (out.back() != '/' && out.back() != '\\') out.push_back('/');
  out += name;
  return out;
}

std::string parent_directory(const std::string& path) {
  if (path.empty()) return {};
  const auto pos = path.find_last_of("/\\");
  if (pos == std::string::npos) return {};
  if (pos == 0) return path.substr(0, 1);
  if (pos == 2 && path.size() > 2 && path[1] == ':') return path.substr(0, 3);
  return path.substr(0, pos);
}

std::string temp_directory() {
  const char* keys[] = {"TMPDIR", "TEMP", "TMP"};
  for (const char* key : keys) {
    if (const char* value = std::getenv(key); value != nullptr && *value != '\0') {
      return value;
    }
  }
#ifdef _WIN32
  return "C:/Windows/Temp";
#else
  return "/tmp";
#endif
}

}  // namespace subconv::fs
