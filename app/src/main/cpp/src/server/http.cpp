// 极简 HTTP/1.1 服务 + 路由（M5）
//
// 刻意不引第三方 HTTP 库：只需要「收一个请求、回一个响应」，与项目「手写 YAML / Base64」的
// 取向一致。单线程、一次一连接、Connection: close —— 本地个人工具足够，且没有并发状态。
//
// 路由：
//   GET  /                     内嵌 Web UI
//   GET  /api/version          版本 / 已实现目标 / libcurl 状态
//   GET  /api/rulesets         分流规则集目录（Web UI 渲染复选列表用）
//   GET  /api/dns              DNS 预设目录（Web UI 渲染复选列表用）
//   POST /api/convert          JSON 进、JSON 出（Web UI 使用）
//   GET  /sub?target=&url=...  subconverter 兼容子集，直接返回配置文本
//   GET  /clash /xray /sing-box?...  同上（路径即目标）
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#include "subconv/codec.hpp"
#include "subconv/console.hpp"
#include "subconv/json.hpp"
#include "subconv/server.hpp"
#include "web_ui.hpp"

namespace subconv::server {
namespace {

#ifdef SUBCONV_VERSION
constexpr const char* kVersion = SUBCONV_VERSION;
#else
constexpr const char* kVersion = "dev";
#endif

constexpr std::size_t kMaxHeaderBytes = 64 * 1024;
constexpr std::size_t kMaxBodyBytes = 16 * 1024 * 1024;
constexpr int kIoTimeoutSeconds = 20;

#ifdef _WIN32
using socket_t = SOCKET;
constexpr socket_t kInvalidSocket = INVALID_SOCKET;
void close_socket(socket_t fd) noexcept { ::closesocket(fd); }
#else
using socket_t = int;
constexpr socket_t kInvalidSocket = -1;
void close_socket(socket_t fd) noexcept { ::close(fd); }
#endif

#ifdef MSG_NOSIGNAL
constexpr int kSendFlags = MSG_NOSIGNAL;  // 避免向已关闭的连接写入时进程被 SIGPIPE 杀掉
#else
constexpr int kSendFlags = 0;
#endif

struct SocketGuard {
  socket_t fd = kInvalidSocket;
  SocketGuard() = default;
  explicit SocketGuard(socket_t handle) noexcept : fd(handle) {}
  ~SocketGuard() {
    if (fd != kInvalidSocket) close_socket(fd);
  }
  SocketGuard(const SocketGuard&) = delete;
  SocketGuard& operator=(const SocketGuard&) = delete;

  void reset(socket_t handle) noexcept {
    if (fd != kInvalidSocket) close_socket(fd);
    fd = handle;
  }
  [[nodiscard]] bool valid() const noexcept { return fd != kInvalidSocket; }

  /// 交出所有权（本守卫不再负责关闭）。给「把 fd 移交给别人管」的场景用。
  [[nodiscard]] socket_t release() noexcept {
    const socket_t handle = fd;
    fd = kInvalidSocket;
    return handle;
  }
};

#ifdef _WIN32
struct WinsockGuard {
  bool ok = false;
  WinsockGuard() {
    WSADATA data{};
    ok = ::WSAStartup(MAKEWORD(2, 2), &data) == 0;
  }
  ~WinsockGuard() {
    if (ok) ::WSACleanup();
  }
};
#endif

// ---------------------------------------------------------------------------
// 停止支持（给嵌入式宿主用：Android 上服务要随 Activity 开关，见 server.hpp）
//
// accept() 阻塞在系统调用里时，光靠「检查一个标志」是退不出来的，得先把循环叫醒。
// 这里用两条互补的路子，任何一条成立都能让 run() 及时返回：
//   1. request_stop() 对监听套接字 shutdown()：Linux/Android 上这会让 accept() 立刻返回；
//   2. 循环里不是裸阻塞 accept()，而是先 poll() 带 500ms 超时 —— 就算第 1 条在某平台上
//      叫不醒（Windows 的 shutdown 对监听套接字无效），最多一个超时周期也会回到标志检查。
//
// 监听 fd 的「登记 → shutdown → 注销 → close」必须整体串行化，否则会出现这样的竞态：
// request_stop() 读到 fd，此时 run() 正好返回并把 fd close 掉，操作系统把它分配给了
// 新的连接 —— 接着那句 shutdown() 就打在了别人身上。所以这里不用 atomic，改用一把锁，
// 并且让 fd 的所有权落在 ListenerRegistration 手上、在锁内关闭。
// ---------------------------------------------------------------------------
std::mutex g_listener_mutex;
socket_t g_listener_fd = kInvalidSocket;  ///< 由 g_listener_mutex 保护
std::atomic<bool> g_stop_requested{false};

/// 接管监听 fd：登记给 request_stop() 用，并在析构时（锁内）关闭它。
struct ListenerRegistration {
  socket_t fd = kInvalidSocket;

  explicit ListenerRegistration(SocketGuard& guard) : fd(guard.release()) {
    std::lock_guard<std::mutex> lock(g_listener_mutex);
    g_listener_fd = fd;
  }

  ~ListenerRegistration() {
    std::lock_guard<std::mutex> lock(g_listener_mutex);
    g_listener_fd = kInvalidSocket;
    if (fd != kInvalidSocket) close_socket(fd);
  }

  ListenerRegistration(const ListenerRegistration&) = delete;
  ListenerRegistration& operator=(const ListenerRegistration&) = delete;
};

/// 等监听套接字可读，最多 wait_ms 毫秒。返回 >0 可读、0 超时、<0 出错。
int wait_readable(socket_t fd, int wait_ms) {
#ifdef _WIN32
  WSAPOLLFD entry{};
  entry.fd = fd;
  entry.events = POLLRDNORM;
  return ::WSAPoll(&entry, 1, wait_ms);
#else
  pollfd entry{};
  entry.fd = fd;
  entry.events = POLLIN;
  return ::poll(&entry, 1, wait_ms);
#endif
}

void set_io_timeout(socket_t fd, int seconds) {
#ifdef _WIN32
  const DWORD ms = static_cast<DWORD>(seconds) * 1000;
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
  ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
#else
  timeval tv{};
  tv.tv_sec = seconds;
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

// ---------------------------------------------------------------------------
// 请求 / 响应
// ---------------------------------------------------------------------------
struct HttpRequest {
  std::string method;
  std::string target;   ///< 原始请求目标，如 /sub?target=clash
  std::string path;
  std::string query;
  std::map<std::string, std::string> headers;   ///< 键统一小写
  std::string body;

  [[nodiscard]] std::string header(std::string_view name) const {
    const auto it = headers.find(codec::to_lower(name));
    return it == headers.end() ? std::string() : it->second;
  }
};

struct HttpResponse {
  int status = 200;
  std::string content_type = "text/plain; charset=utf-8";
  std::string body;
  std::vector<std::pair<std::string, std::string>> headers;
};

const char* status_text(int status) {
  switch (status) {
    case 200: return "OK";
    case 204: return "No Content";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 413: return "Payload Too Large";
    case 500: return "Internal Server Error";
    default: return "OK";
  }
}

std::string serialize(const HttpResponse& res) {
  std::string out;
  out.reserve(res.body.size() + 320);
  out += "HTTP/1.1 ";
  out += std::to_string(res.status);
  out += ' ';
  out += status_text(res.status);
  out += "\r\nContent-Type: ";
  out += res.content_type;
  out += "\r\nContent-Length: ";
  out += std::to_string(res.body.size());
  out += "\r\nCache-Control: no-store\r\nConnection: close\r\nX-Subconv-Version: ";
  out += kVersion;
  out += "\r\n";
  for (const auto& [name, value] : res.headers) {
    out += name;
    out += ": ";
    out += value;
    out += "\r\n";
  }
  out += "\r\n";
  out += res.body;
  return out;
}

bool send_all(socket_t fd, std::string_view data) {
  std::size_t sent = 0;
  while (sent < data.size()) {
    const int n = ::send(fd, data.data() + sent, static_cast<int>(data.size() - sent), kSendFlags);
    if (n <= 0) return false;
    sent += static_cast<std::size_t>(n);
  }
  return true;
}

bool read_into(socket_t fd, std::string& buffer, std::size_t want) {
  char chunk[8192];
  while (buffer.size() < want) {
    const int n = ::recv(fd, chunk, static_cast<int>(sizeof(chunk)), 0);
    if (n <= 0) return false;
    buffer.append(chunk, static_cast<std::size_t>(n));
  }
  return true;
}

/// 解析一个请求；失败返回 false（调用方直接关闭连接）。
bool recv_request(socket_t fd, HttpRequest& out, bool& too_large) {
  std::string buffer;
  char chunk[8192];
  std::size_t header_end = std::string::npos;
  while (header_end == std::string::npos) {
    const int n = ::recv(fd, chunk, static_cast<int>(sizeof(chunk)), 0);
    if (n <= 0) return false;
    buffer.append(chunk, static_cast<std::size_t>(n));
    header_end = buffer.find("\r\n\r\n");
    if (header_end == std::string::npos && buffer.size() > kMaxHeaderBytes) return false;
  }

  const std::string head = buffer.substr(0, header_end);
  std::string body = buffer.substr(header_end + 4);

  const auto line_end = head.find("\r\n");
  const std::string request_line =
      line_end == std::string::npos ? head : head.substr(0, line_end);

  const auto first_space = request_line.find(' ');
  if (first_space == std::string::npos) return false;
  const auto second_space = request_line.find(' ', first_space + 1);
  if (second_space == std::string::npos) return false;
  out.method = request_line.substr(0, first_space);
  out.target = request_line.substr(first_space + 1, second_space - first_space - 1);

  const auto question = out.target.find('?');
  if (question == std::string::npos) {
    out.path = out.target;
  } else {
    out.path = out.target.substr(0, question);
    out.query = out.target.substr(question + 1);
  }

  // 头部
  std::size_t pos = line_end == std::string::npos ? head.size() : line_end + 2;
  while (pos < head.size()) {
    const auto end = head.find("\r\n", pos);
    const std::string line = head.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
    pos = end == std::string::npos ? head.size() : end + 2;
    if (line.empty()) continue;
    const auto colon = line.find(':');
    if (colon == std::string::npos) continue;
    out.headers[codec::to_lower(codec::trim(std::string_view(line).substr(0, colon)))] =
        codec::trim(std::string_view(line).substr(colon + 1));
  }

  // Expect: 100-continue —— curl 在 body 较大时会先等这个响应，不理会会白等 1 秒
  if (codec::to_lower(out.header("expect")).find("100-continue") != std::string::npos) {
    send_all(fd, "HTTP/1.1 100 Continue\r\n\r\n");
  }

  std::size_t content_length = 0;
  const std::string length_header = out.header("content-length");
  if (!length_header.empty()) {
    content_length = static_cast<std::size_t>(std::strtoul(length_header.c_str(), nullptr, 10));
  }
  if (content_length > kMaxBodyBytes) {
    too_large = true;
    return false;
  }
  if (!read_into(fd, body, content_length)) return false;
  body.resize(std::min(body.size(), content_length));
  out.body = std::move(body);
  return true;
}

// ---------------------------------------------------------------------------
// 响应构造
// ---------------------------------------------------------------------------
std::string sanitize_filename_ascii(std::string_view name) {
  std::string out;
  out.reserve(name.size());
  for (const char ch : name) {
    const auto c = static_cast<unsigned char>(ch);
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' ||
        c == '-' || c == '_') {
      out.push_back(ch);
    } else {
      out.push_back('_');
    }
  }
  if (out.empty()) out = "config.txt";
  return out;
}

std::string content_disposition(const std::string& filename) {
  return "attachment; filename=\"" + sanitize_filename_ascii(filename) + "\"; filename*=UTF-8''" +
         codec::percent_encode(filename);
}

std::string userinfo_header(const SubscriptionInfo& info) {
  return "upload=" + std::to_string(info.upload) + "; download=" + std::to_string(info.download) +
         "; total=" + std::to_string(info.total) + "; expire=" + std::to_string(info.expire);
}

HttpResponse json_response(int status, const Json& payload) {
  HttpResponse res;
  res.status = status;
  res.content_type = "application/json; charset=utf-8";
  res.body = payload.dump(2);
  return res;
}

HttpResponse error_json(int status, const std::string& message) {
  Json payload = Json::object();
  payload["ok"] = false;
  payload["error"] = message;
  return json_response(status, payload);
}

HttpResponse text_response(int status, const std::string& message) {
  HttpResponse res;
  res.status = status;
  res.body = message + "\n";
  return res;
}

bool want_json(const HttpRequest& req) {
  const std::string accept = codec::to_lower(req.header("accept"));
  const std::string xhr = codec::to_lower(req.header("x-requested-with"));
  return accept.find("application/json") != std::string::npos || xhr == "xmlhttprequest";
}

/// 统一的失败响应：浏览器 UI 走 JSON，curl 走纯文本（更好读）。
HttpResponse failure(const HttpRequest& req, int status, const std::string& message) {
  if (req.path == "/api/convert" || want_json(req)) return error_json(status, message);
  return text_response(status, "subconv: " + message);
}

Json version_payload() {
  Json payload = Json::object();
  payload["name"] = "subconv";
  payload["version"] = kVersion;
  payload["targets"] = implemented_targets();
  payload["planned"] = planned_targets();
  payload["curl"] = fetch::http_available();
  return payload;
}

// ---------------------------------------------------------------------------
// 路由
// ---------------------------------------------------------------------------
HttpResponse handle(const HttpRequest& req, const ServerOptions& opts) {
  if (req.method != "GET" && req.method != "POST") {
    return failure(req, 405, "只支持 GET 与 POST");
  }

  if (req.path == "/" || req.path == "/index.html") {
    HttpResponse res;
    res.content_type = "text/html; charset=utf-8";
    res.body = kWebUiHtml;
    return res;
  }
  if (req.path == "/favicon.ico") {
    return HttpResponse{204, "text/plain", "", {}};
  }
  if (req.path == "/api/version" || req.path == "/version") {
    return json_response(200, version_payload());
  }
  if (req.path == "/api/rulesets" || req.path == "/rulesets") {
    // Web UI 靠这个端点渲染「规则集」复选列表 —— 目录只有 C++ 一份，避免两端写死不同步
    Json payload = Json::object();
    Json list = Json::array();
    for (const auto& rs : rule_set_catalogue()) {
      Json item = Json::object();
      item["id"] = rs.id;
      item["name"] = rs.name;
      item["policy"] = rs.policy;
      item["note"] = rs.note;
      list.push_back(std::move(item));
    }
    payload["rulesets"] = std::move(list);
    payload["default"] = default_rule_sets();
    return json_response(200, payload);
  }
  if (req.path == "/api/dns" || req.path == "/dns") {
    // 同 /api/rulesets：DNS 预设目录也只有 C++ 一份
    Json payload = Json::object();
    Json list = Json::array();
    for (const auto& preset : dns_catalogue()) {
      Json item = Json::object();
      item["id"] = preset.id;
      item["name"] = preset.name;
      item["region"] = preset.region;
      item["note"] = preset.note;
      item["v4"] = preset.v4;
      item["v6"] = preset.v6;
      list.push_back(std::move(item));
    }
    payload["presets"] = std::move(list);
    payload["default"] = default_dns();
    return json_response(200, payload);
  }

  if (req.path == "/api/convert") {
    if (req.method != "POST") {
      return failure(req, 405, "POST /api/convert 需要 JSON 请求体");
    }
    auto request = request_from_json(req.body, opts);
    if (!request) return failure(req, 400, request.error().message);

    auto result = convert(*request);
    if (!result) return failure(req, 400, result.error().message);

    Json payload = Json::object();
    payload["ok"] = true;
    payload["target"] = normalize_target(request->emit.target);
    payload["filename"] = result->filename;
    payload["nodes"] = result->nodes;
    payload["config"] = result->config;
    payload["warnings"] = result->warnings;
    Json info = Json::object();
    info["upload"] = result->info.upload;
    info["download"] = result->info.download;
    info["total"] = result->info.total;
    info["expire"] = result->info.expire;
    payload["info"] = std::move(info);
    return json_response(200, payload);
  }

  const std::string hinted = target_from_path(req.path);
  if (req.path == "/sub" || !hinted.empty()) {
    ServerOptions effective = opts;
    if (!hinted.empty()) effective.default_target = hinted;

    auto request = request_from_query(req.query, effective);
    if (!request) return failure(req, 400, request.error().message);

    auto result = convert(*request);
    if (!result) return failure(req, 400, result.error().message);

    HttpResponse res;
    const std::string canonical = normalize_target(request->emit.target);
    if (canonical == "clash") {
      res.content_type = "text/yaml; charset=utf-8";
    } else if (canonical == "links" || canonical == "base64" || canonical == "v2rayn") {
      // v2rayNG / v2rayN 期望拿到纯文本链接列表
      res.content_type = "text/plain; charset=utf-8";
    } else {
      res.content_type = "application/json; charset=utf-8";
    }
    res.body = result->config;
    res.headers.emplace_back("Content-Disposition", content_disposition(result->filename));
    if (result->info.has_any()) {
      res.headers.emplace_back("subscription-userinfo", userinfo_header(result->info));
    }
    res.headers.emplace_back("Profile-Update-Interval", "24");
    return res;
  }

  return failure(req, 404,
                  "未知路径 " + req.path +
                      "。可用：/ (Web UI)、/sub?target=&url=、/clash|/xray|/sing-box?url=、"
                      "/api/version、/api/rulesets、/api/dns、POST /api/convert");
}

void handle_connection(socket_t fd, const ServerOptions& opts) {
  set_io_timeout(fd, kIoTimeoutSeconds);

  HttpRequest request;
  bool too_large = false;
  if (!recv_request(fd, request, too_large)) {
    if (too_large) {
      const HttpResponse res = text_response(413, "subconv: 请求体过大（上限 16 MB）");
      send_all(fd, serialize(res));
    }
    return;
  }
  if (opts.verbose) {
    console::write_line(stderr, "[http] " + request.method + " " + request.target);
  }
  const HttpResponse res = handle(request, opts);
  send_all(fd, serialize(res));
}

std::string display_host(const std::string& listen) {
  if (listen.empty() || listen == "0.0.0.0") return "127.0.0.1";
  if (listen == "::" || listen == "[::]") return "[::1]";
  if (listen.find(':') != std::string::npos && listen.front() != '[') return "[" + listen + "]";
  return listen;
}

void open_browser(const std::string& url) {
#if defined(_WIN32)
  const std::string command = "start \"\" \"" + url + "\"";
#else
  const std::string command = "xdg-open \"" + url + "\" >/dev/null 2>&1";
#endif
  if (std::system(command.c_str()) != 0) {
    console::write_line(stderr, "提示: 无法自动打开浏览器，请手动访问 " + url);
  }
}

}  // namespace

void request_stop() noexcept {
  g_stop_requested.store(true, std::memory_order_release);
  // 「取 fd + shutdown」和「注销 + close」必须互斥，否则可能 shutdown 到一个已经被关闭、
  // 甚至已被系统回收给别的套接字的 fd 号上（见上面那段注释）。
  std::lock_guard<std::mutex> lock(g_listener_mutex);
  if (g_listener_fd == kInvalidSocket) return;
  // 叫醒阻塞中的 accept()：Linux/Android 上对监听套接字 shutdown() 会让它立刻返回。
  // 失败也无所谓 —— 循环里 poll() 的超时兜底，最坏一个周期后照样退出。
  ::shutdown(g_listener_fd, SHUT_RDWR);
}

Result<void> run(const ServerOptions& opts, const ReadyHandler& on_ready) {
  // 上一次 request_stop() 不该影响这一次启动（同一个进程里服务会反复开关）
  g_stop_requested.store(false, std::memory_order_release);
#ifdef _WIN32
  WinsockGuard winsock;
  if (!winsock.ok) return fail("WSAStartup 失败：WinSock 初始化未成功");
#endif

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  const std::string port_text = std::to_string(opts.port);

  addrinfo* candidates = nullptr;
  const int rc = ::getaddrinfo(opts.listen.c_str(), port_text.c_str(), &hints, &candidates);
  if (rc != 0) {
    return fail(std::string("无法解析监听地址 ") + opts.listen + "：" +
                (::gai_strerror(rc) != nullptr ? ::gai_strerror(rc) : "未知错误"));
  }

  SocketGuard listener;
  int bound_port = opts.port;
  for (addrinfo* it = candidates; it != nullptr; it = it->ai_next) {
    const socket_t fd = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (fd == kInvalidSocket) continue;

    const int yes = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));
    if (::bind(fd, it->ai_addr, static_cast<int>(it->ai_addrlen)) != 0 ||
        ::listen(fd, 32) != 0) {
      close_socket(fd);
      continue;
    }
    listener.reset(fd);

    sockaddr_storage local{};
    socklen_t local_len = sizeof(local);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&local), &local_len) == 0) {
      if (local.ss_family == AF_INET) {
        bound_port = ntohs(reinterpret_cast<sockaddr_in*>(&local)->sin_port);
      } else if (local.ss_family == AF_INET6) {
        bound_port = ntohs(reinterpret_cast<sockaddr_in6*>(&local)->sin6_port);
      }
    }
    break;
  }
  ::freeaddrinfo(candidates);

  if (!listener.valid()) {
    return fail("无法监听 " + opts.listen + ":" + port_text + "（端口被占用，或该地址不可用）");
  }

  // 接管 listener 手里的 fd：从这里开始 request_stop() 能找到这个套接字，
  // 并且 fd 会由它在析构时（锁内）关闭。listener 自此为空守卫。
  ListenerRegistration registration(listener);

  const std::string url = "http://" + display_host(opts.listen) + ":" + std::to_string(bound_port) + "/";
  console::write_line(stdout, "Web UI: " + url);
  console::write_line(stdout, "API: /sub?target=clash&url=<订阅链接>  |  POST /api/convert  |  /api/version  |  /api/rulesets  |  /api/dns");
  std::fflush(stdout);

  if (opts.port != bound_port) {
    console::write_line(stderr, "已由系统分配端口 " + std::to_string(bound_port));
  }
  if (opts.open_browser) open_browser(url);

  // 监听已经成功、端口已经是最终值 —— 现在告诉宿主（Android 的 WebView 拿它拼 URL）。
  // 必须在 accept 循环之前：宿主拿到端口就会去加载页面，越早越好。
  if (on_ready) on_ready(url, bound_port);

  int consecutive_errors = 0;
  for (;;) {
    if (g_stop_requested.load(std::memory_order_acquire)) return {};

    // 先 poll 再 accept：poll 的超时让「停止」在任何平台上都有确定的退出时机，
    // 不必依赖「另一个线程能不能把阻塞中的 accept 叫醒」这件平台相关的事。
    const int ready = wait_readable(registration.fd, 500);
    if (ready == 0) {
      consecutive_errors = 0;
      continue;  // 超时：回到循环头部看停止标志
    }
    if (ready < 0) {
      if (g_stop_requested.load(std::memory_order_acquire)) return {};
      if (++consecutive_errors >= 16) return fail("poll 连续失败，服务退出");
      continue;
    }

    sockaddr_storage peer{};
    socklen_t peer_len = sizeof(peer);
    const socket_t client = ::accept(registration.fd, reinterpret_cast<sockaddr*>(&peer), &peer_len);
    if (client == kInvalidSocket) {
      if (g_stop_requested.load(std::memory_order_acquire)) return {};
      if (++consecutive_errors >= 16) {
        return fail("accept 连续失败，服务退出");
      }
      continue;
    }
    consecutive_errors = 0;

    SocketGuard connection(client);
    handle_connection(client, opts);
  }
}

}  // namespace subconv::server
