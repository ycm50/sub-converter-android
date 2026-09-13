// 对端证书指纹探测（Xray `pinnedPeerCertSha256` 的来源）
//
// 为什么需要它：
//   Xray 25 起彻底移除了 `allowInsecure`，报错原文是
//     The feature "allowInsecure" has been removed and migrated to
//     "pinnedPeerCertSha256"(pcs) and "verifyPeerCertByName"(vcn).
//   而 vcn 仍然要求「证书链可信 **且** 名字匹配」（transport/internet/tls/config.go 的
//   RandCarrier.verifyPeerCert -> certs[0].Verify(opts)），机场常见的做法恰恰是让节点证书
//   与 SNI 对不上（实测一元机场：SNI=update.microsoft.com，
//   证书 CN=new.download.the-best-airport.com），于是 `-t xray` 的产物必然握手失败：
//     transport/internet/tls: peer cert is invalid (against root CAs and verifyPeerCertByName)
//   客户端上的表现就是「所有节点延迟 -1」。
//
//   同一份代码里，指纹命中**叶子证书**时是直接 `return nil`（foundLeaf 分支，不再校链、不再校名）：
//   于是「连上去看证书 → 写指纹」成了 Xray 官方给出的唯一替代路径，也就是这里做的事。
//
// 只在 `--probe-cert` 时启用：它需要主动连接每个节点（转换器平时只做本地转换）。
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <string_view>

#include "subconv/codec.hpp"
#include "subconv/fetch.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
// 非阻塞 connect 依赖 fcntl/F_GETFL/O_NONBLOCK（POSIX 定义在 <fcntl.h>，不是 <unistd.h>），
// errno/EINPROGRESS 来自 <cerrno>。glibc 之外（musl / bionic）不会顺带引入，必须显式包含。
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#ifdef SUBCONV_HAVE_OPENSSL
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#elif defined(SUBCONV_HAVE_ANDROID_HTTP)
#include "subconv/android_http.hpp"
#endif

namespace subconv::fetch {
#ifdef SUBCONV_HAVE_OPENSSL
namespace {

#ifdef _WIN32
using SocketHandle = SOCKET;
constexpr SocketHandle kInvalidSocket = INVALID_SOCKET;

struct WinsockGuard {
  bool ok = false;
  WinsockGuard() {
    WSADATA data{};
    ok = ::WSAStartup(MAKEWORD(2, 2), &data) == 0;
  }
  ~WinsockGuard() {
    if (ok) ::WSACleanup();
  }
  WinsockGuard(const WinsockGuard&) = delete;
  WinsockGuard& operator=(const WinsockGuard&) = delete;
};

void close_socket(SocketHandle s) { ::closesocket(s); }
int last_socket_error() { return ::WSAGetLastError(); }
constexpr int kInProgress = WSAEWOULDBLOCK;
#else
using SocketHandle = int;
constexpr SocketHandle kInvalidSocket = -1;

struct WinsockGuard {
  bool ok = true;
};

void close_socket(SocketHandle s) { ::close(s); }
int last_socket_error() { return errno; }
constexpr int kInProgress = EINPROGRESS;
#endif

/// 带超时的连接：非阻塞 connect + select。返回套接字（失败返回 kInvalidSocket）。
SocketHandle connect_with_timeout(const std::string& host, uint16_t port, int timeout_ms,
                                  std::string& error) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  addrinfo* list = nullptr;
  const std::string port_text = std::to_string(port);
  const int gai = ::getaddrinfo(host.c_str(), port_text.c_str(), &hints, &list);
  if (gai != 0 || list == nullptr) {
#ifdef _WIN32
    error = "域名解析失败（" + host + "）";
#else
    error = std::string("域名解析失败（") + host + "）：" + ::gai_strerror(gai);
#endif
    if (list != nullptr) ::freeaddrinfo(list);
    return kInvalidSocket;
  }

  SocketHandle sock = kInvalidSocket;
  for (addrinfo* it = list; it != nullptr; it = it->ai_next) {
    sock = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (sock == kInvalidSocket) continue;

    // 非阻塞 connect，用 select 等可写
#ifdef _WIN32
    u_long nonblocking = 1;
    ::ioctlsocket(sock, FIONBIO, &nonblocking);
#else
    const int flags = ::fcntl(sock, F_GETFL, 0);
    ::fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif
    const int rc = ::connect(sock, it->ai_addr, static_cast<int>(it->ai_addrlen));
    if (rc == 0) break;

    if (last_socket_error() != kInProgress) {
      close_socket(sock);
      sock = kInvalidSocket;
      continue;
    }

    fd_set writable;
    FD_ZERO(&writable);
    FD_SET(sock, &writable);
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    const int ready = ::select(static_cast<int>(sock) + 1, nullptr, &writable, nullptr, &tv);
    if (ready <= 0) {
      close_socket(sock);
      sock = kInvalidSocket;
      error = "连接超时（" + host + ":" + port_text + "）";
      continue;
    }
    int so_error = 0;
#ifdef _WIN32
    int len = sizeof(so_error);
#else
    socklen_t len = sizeof(so_error);
#endif
    ::getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_error), &len);
    if (so_error != 0) {
      close_socket(sock);
      sock = kInvalidSocket;
      error = "连接失败（" + host + ":" + port_text + "）";
      continue;
    }
    break;  // 连上了
  }
  ::freeaddrinfo(list);

  if (sock == kInvalidSocket) {
    if (error.empty()) error = "无法连接 " + host + ":" + port_text;
    return sock;
  }

  // 恢复阻塞，并给后续 TLS 读写设超时
#ifdef _WIN32
  u_long blocking = 0;
  ::ioctlsocket(sock, FIONBIO, &blocking);
  DWORD tv = static_cast<DWORD>(timeout_ms);
  ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
  ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
  const int flags = ::fcntl(sock, F_GETFL, 0);
  ::fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
  timeval tv{};
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
  return sock;
}

std::string to_hex_fingerprint(const unsigned char* data, unsigned int len) {
  static const char* kHex = "0123456789ABCDEF";
  std::string out;
  out.reserve(len * 3);
  for (unsigned int i = 0; i < len; ++i) {
    if (i != 0) out.push_back(':');
    out.push_back(kHex[data[i] >> 4]);
    out.push_back(kHex[data[i] & 0x0F]);
  }
  return out;
}

}  // namespace

Result<std::string> probe_peer_cert_sha256(std::string_view host, uint16_t port,
                                          std::string_view sni, int timeout_seconds) {
  if (host.empty() || port == 0) return fail("探测证书需要合法的 host:port");
  const int timeout_ms = (timeout_seconds > 0 ? timeout_seconds : 5) * 1000;

  WinsockGuard winsock;
  if (!winsock.ok) return fail("WSAStartup 失败，无法建立 TLS 连接");

  std::string error;
  const SocketHandle sock = connect_with_timeout(std::string(host), port, timeout_ms, error);
  if (sock == kInvalidSocket) return fail(error);

  SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
  if (ctx == nullptr) {
    close_socket(sock);
    return fail("SSL_CTX_new 失败");
  }
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  // 这里就是要"不管证书对不对先连上"，与 Xray pcs 的语义一致
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

  SSL* ssl = SSL_new(ctx);
  if (ssl == nullptr) {
    SSL_CTX_free(ctx);
    close_socket(sock);
    return fail("SSL_new 失败");
  }
  SSL_set_fd(ssl, static_cast<int>(sock));
  // 没给 sni 时按惯例用 host。IP 字面量也照设不误：TLS 规范不允许 IP 当 SNI，OpenSSL 会
  // 自己忽略，但个别节点确实按 SNI 分流，宁可多设一次也别漏。
  const std::string server_name = sni.empty() ? std::string(host) : std::string(sni);
  if (!server_name.empty()) {
    SSL_set_tlsext_host_name(ssl, server_name.c_str());
  }
  SSL_set_connect_state(ssl);

  std::string result;
  std::string failure;
  if (SSL_connect(ssl) != 1) {
    const unsigned long code = ERR_get_error();
    char text[256] = {0};
    if (code != 0) ERR_error_string_n(code, text, sizeof(text));
    failure = "TLS 握手失败（" + server_name + "）" + (text[0] != 0 ? std::string("：") + text : "");
  } else {
    X509* cert = SSL_get1_peer_certificate(ssl);
    if (cert == nullptr) {
      failure = "对端没有提供证书";
    } else {
      unsigned char* der = nullptr;
      const int der_len = i2d_X509(cert, &der);
      if (der_len <= 0 || der == nullptr) {
        failure = "证书 DER 编码失败";
      } else {
        unsigned char digest[EVP_MAX_MD_SIZE] = {0};
        unsigned int digest_len = 0;
        if (EVP_Digest(der, static_cast<std::size_t>(der_len), digest, &digest_len,
                       EVP_sha256(), nullptr) != 1) {
          failure = "证书 SHA256 计算失败";
        } else {
          result = to_hex_fingerprint(digest, digest_len);
        }
        OPENSSL_free(der);
      }
      X509_free(cert);
    }
  }

  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  close_socket(sock);

  if (!failure.empty()) return fail(failure);
  return result;
}

#elif defined(SUBCONV_HAVE_ANDROID_HTTP)

// Android 没有 OpenSSL：握手与取证书交给 Java 的 SSLSocket（用「信任所有」的
// TrustManager，好让证书与 SNI 对不上时也能拿到链，语义与上游一致），
// 指纹仍然算在叶子证书的 DER 上，输出格式完全一样。
Result<std::string> probe_peer_cert_sha256(std::string_view host, uint16_t port,
                                          std::string_view sni, int timeout_seconds) {
  return android::probe_peer_cert_sha256(host, port, sni, timeout_seconds);
}

#else  // 既没有 OpenSSL 也没有 Android 桥

Result<std::string> probe_peer_cert_sha256(std::string_view host, uint16_t port,
                                          std::string_view sni, int timeout_seconds) {
  (void)host;
  (void)port;
  (void)sni;
  (void)timeout_seconds;
  return fail("本次构建未启用证书探测后端（OpenSSL 或 Android 桥），--probe-cert 不可用");
}

#endif

std::size_t probe_node_certificates(NodeList& nodes, int timeout_seconds,
                                    std::vector<std::string>* warnings) {
  std::map<std::string, std::string> cache;  // host:port|sni -> 指纹（同一次运行内不重复探测）
  std::size_t probed = 0;

  auto probe_cached = [&](const std::string& host, uint16_t port, const std::string& sni,
                          std::string& out, std::string& error) -> bool {
    const std::string key = host + ":" + std::to_string(port) + "|" + sni;
    const auto it = cache.find(key);
    if (it != cache.end()) {
      if (it->second.empty()) {
        error = "先前探测已失败";
        return false;
      }
      out = it->second;
      return true;
    }
    auto result = probe_peer_cert_sha256(host, port, sni, timeout_seconds);
    if (!result) {
      cache[key] = std::string();
      error = result.error().message;
      return false;
    }
    cache[key] = *result;
    out = *result;
    ++probed;
    return true;
  };

  for (auto& node : nodes) {
    if (!node.is_tls()) continue;
    const bool main_insecure = node.tls.insecure || node.scv;

    if (main_insecure && node.tls.pinned_cert_sha256.empty() && !node.server.empty() &&
        node.port != 0) {
      std::string fingerprint;
      std::string error;
      if (probe_cached(node.server, node.port, node.tls.sni, fingerprint, error)) {
        node.tls.pinned_cert_sha256 = fingerprint;
      } else if (warnings != nullptr) {
        warnings->push_back("节点 " + node.name + " 证书探测失败：" + error);
      }
    }

    if (node.network != Network::Xhttp || !node.xhttp.download.present) continue;
    const XhttpDownloadOptions& d = node.xhttp.download;
    // 下载侧同样要跳过校验时才需要指纹（没写就沿用主节点）
    if (!d.insecure.value_or(main_insecure)) continue;
    const bool download_tls = d.tls.value_or(node.tls.enabled);
    if (!download_tls) continue;

    const std::string host = d.server.empty() ? node.server : d.server;
    const uint16_t port = d.port.value_or(node.port);
    const std::string sni = d.sni.empty() ? node.tls.sni : d.sni;
    if (host.empty() || port == 0) continue;

    std::string fingerprint;
    std::string error;
    if (probe_cached(host, port, sni, fingerprint, error)) {
      node.xhttp.download.pinned_cert_sha256 = fingerprint;
    } else if (warnings != nullptr) {
      warnings->push_back("节点 " + node.name + " 下载侧证书探测失败：" + error);
    }
  }
  return probed;
}

}  // namespace subconv::fetch
