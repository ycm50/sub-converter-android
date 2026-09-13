// HTTP 客户端封装
//
// 后端二选一，由编译期开关决定，上层（重试 / 嗅探 / 缓存 / emit）完全无感：
//   * 桌面 / CLI：libcurl（上游的写法，SUBCONV_HAVE_CURL）
//   * Android   ：转调 Java 的 HttpURLConnection（NDK 不带 libcurl）
//                 —— 见 src/fetch/android_http.cpp
#include "subconv/fetch.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include "subconv/codec.hpp"
#include "subconv/console.hpp"

#ifdef SUBCONV_HAVE_CURL
#include <curl/curl.h>
#elif defined(SUBCONV_HAVE_ANDROID_HTTP)
#include "subconv/android_http.hpp"
#endif

namespace subconv::fetch {
namespace {

#ifdef SUBCONV_HAVE_CURL

/// libcurl 全局初始化的 RAII 守卫（进程内只做一次）。
struct CurlGlobal {
  CurlGlobal() { curl_global_init(CURL_GLOBAL_DEFAULT); }
  ~CurlGlobal() { curl_global_cleanup(); }
};

void ensure_global() { static CurlGlobal guard; }

std::size_t write_cb(char* ptr, std::size_t size, std::size_t nmemb, void* userdata) {
  auto* body = static_cast<std::string*>(userdata);
  const std::size_t total = size * nmemb;
  if (body->size() + total > 64u * 1024 * 1024) return 0;  // 64MB 上限，防御异常响应
  body->append(ptr, total);
  return total;
}

std::size_t header_cb(char* buffer, std::size_t size, std::size_t nitems, void* userdata) {
  auto* headers = static_cast<std::map<std::string, std::string>*>(userdata);
  const std::size_t total = size * nitems;
  const std::string line(buffer, total);
  const auto colon = line.find(':');
  if (colon != std::string::npos && colon > 0) {
    const std::string key = codec::to_lower(codec::trim(std::string_view(line).substr(0, colon)));
    const std::string value = codec::trim(std::string_view(line).substr(colon + 1));
    if (!key.empty()) (*headers)[key] = value;
  }
  return total;
}

std::string normalize_proxy(std::string proxy) {
  // socks5:// 让代理端做 DNS 解析，避免本地 DNS 污染
  if (codec::starts_with_icase(proxy, "socks5://")) {
    proxy = "socks5h://" + proxy.substr(std::string("socks5://").size());
  }
  return proxy;
}

// ---------------------------------------------------------------------------
// CA 证书包
//
// 背景：libcurl 在 MSYS2 下把 CA bundle 默认指向 <MSYS2>/ucrt64/etc/ssl/certs/ca-bundle.crt。
// 如果 ca-certificates 包没装好，这个文件会是 0 字节 —— 于是每一次 HTTPS 抓取都以
// "error adding trust anchors from file: ..." 失败，而报错完全看不出是证书的问题。
// 这里在默认路径不可用时主动找一个能用的，并让 resolved_ca_bundle() 可诊断。
// ---------------------------------------------------------------------------

/// 一个 CA bundle 是否可用：存在且不是空壳（真实 bundle 至少几十 KB）。
bool usable_bundle(const std::string& path) {
  if (path.empty()) return false;
  std::ifstream in(path, std::ios::binary);
  if (!in) return false;
  in.seekg(0, std::ios::end);
  return in.tellg() >= 4096;
}

/// 问 libcurl：你自己的默认 CA bundle 是哪个？（curl >= 7.84 提供 CURLINFO_CAINFO）
std::string libcurl_default_ca_bundle() {
  CURL* probe = curl_easy_init();
  if (probe == nullptr) return {};
  std::string path;
#if LIBCURL_VERSION_NUM >= 0x075400
  char* reported = nullptr;
  if (curl_easy_getinfo(probe, CURLINFO_CAINFO, &reported) == CURLE_OK && reported != nullptr) {
    path = reported;
  }
#endif
  curl_easy_cleanup(probe);
  return path;
}

/// MSYS2 的布局是 <root>/{ucrt64,clang64,mingw64}/... 与 <root>/usr/...，
/// 前者缺证书时通常后者是好的。把路径里的环境段换成 usr 再试一次。
std::string msys_sibling(const std::string& path) {
  static const char* kEnvs[] = {"ucrt64", "clang64", "mingw64", "clangarm64"};
  for (const char* env : kEnvs) {
    for (const char* sep : {"/", "\\"}) {
      const std::string needle = std::string(1, sep[0]) + env + sep;
      const auto pos = path.find(needle);
      if (pos != std::string::npos) {
        return path.substr(0, pos) + sep + "usr" + sep + path.substr(pos + needle.size());
      }
    }
  }
  return {};
}

/// 由 MSYS2_PREFIX（如 A:/msys64/ucrt64）推出 usr 下的 bundle 路径。
std::string msys_prefix_bundle(const std::string& prefix) {
  const auto cut = prefix.find_last_of("/\\");
  if (cut == std::string::npos || cut == 0) return {};
  const char sep = prefix[cut];
  return prefix.substr(0, cut) + sep + "usr" + sep + "ssl" + sep + "certs" + sep + "ca-bundle.crt";
}

/// 选定 CA bundle；空串表示「用 libcurl 默认，别干预」。
const std::string& ca_bundle_path() {
  static const std::string chosen = [] () -> std::string {
    // 1) 环境变量优先，与 curl 命令行的行为一致
    for (const char* name : {"CURL_CA_BUNDLE", "SSL_CERT_FILE"}) {
      if (const char* value = std::getenv(name); value != nullptr && usable_bundle(value)) {
        return value;
      }
    }

    // 2) libcurl 自带的默认值能用就不插手
    const std::string from_libcurl = libcurl_default_ca_bundle();
    if (usable_bundle(from_libcurl)) return {};

    // 3) 从默认路径与 MSYS2_PREFIX 推导备选
    std::vector<std::string> candidates;
    if (std::string sibling = msys_sibling(from_libcurl); !sibling.empty()) {
      candidates.push_back(std::move(sibling));
    }
    if (const char* prefix = std::getenv("MSYS2_PREFIX"); prefix != nullptr) {
      if (std::string sibling = msys_prefix_bundle(prefix); !sibling.empty()) {
        candidates.push_back(std::move(sibling));
      }
    }
    // 4) 各平台常见位置兜底
    for (const char* path : {
             "A:/msys64/usr/ssl/certs/ca-bundle.crt",
             "C:/msys64/usr/ssl/certs/ca-bundle.crt",
             "C:/Program Files/Git/mingw64/etc/ssl/certs/ca-bundle.crt",
             "C:/Program Files/Git/usr/ssl/certs/ca-bundle.crt",
             "/usr/ssl/certs/ca-bundle.crt",
             "/etc/ssl/certs/ca-certificates.crt",
             "/etc/pki/tls/certs/ca-bundle.crt",
             "/etc/ssl/cert.pem",
         }) {
      candidates.push_back(path);
    }

    for (const std::string& candidate : candidates) {
      if (usable_bundle(candidate)) return candidate;
    }
    return {};  // 实在找不到：保持原样，让 -k 成为唯一出路
  }();
  return chosen;
}

struct StringList {
  curl_slist* list = nullptr;
  ~StringList() {
    if (list != nullptr) curl_slist_free_all(list);
  }
  void add(const std::string& s) { list = curl_slist_append(list, s.c_str()); }
};

#endif  // SUBCONV_HAVE_CURL

}  // namespace

const std::string* HttpResponse::header(std::string_view name) const noexcept {
  const std::string key = codec::to_lower(name);
  const auto it = headers.find(key);
  return it == headers.end() ? nullptr : &it->second;
}

bool http_available() noexcept {
#ifdef SUBCONV_HAVE_CURL
  return true;
#elif defined(SUBCONV_HAVE_ANDROID_HTTP)
  // Android 上「有没有网络能力」取决于 JNI 桥有没有挂好（JNI_OnLoad 是否跑过），
  // 所以这里问一次桥，而不是无脑 true —— /api/version 里那个 curl 字段就是它，
  // Web UI 靠它决定要不要提示「URL 抓取不可用」。
  return android::ready();
#else
  return false;
#endif
}

std::string resolved_ca_bundle() {
#if defined(SUBCONV_HAVE_CURL)
  ensure_global();
  return ca_bundle_path();
#else
  // Android 侧用系统信任的 CA（HttpURLConnection / SSLSocket 自己管），
  // 没有「CA bundle 路径」这个概念，空串就是「不干预」。
  return {};
#endif
}

Result<HttpResponse> http_get(const std::string& url, const HttpOptions& opts) {
#ifdef SUBCONV_HAVE_CURL
  ensure_global();

  CURL* curl = curl_easy_init();
  if (curl == nullptr) return fail("curl_easy_init 失败");

  HttpResponse response;
  StringList request_headers;
  char error_buffer[CURL_ERROR_SIZE] = {0};

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_buffer);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response.body);
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_cb);
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response.headers);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, opts.user_agent.c_str());
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, opts.timeout_seconds);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, opts.connect_timeout_seconds);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");  // 自动解压
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, opts.follow_redirects ? 1L : 0L);
  curl_easy_setopt(curl, CURLOPT_MAXREDIRS, opts.max_redirects);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, opts.insecure ? 0L : 1L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, opts.insecure ? 0L : 2L);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, opts.verbose ? 1L : 0L);

  // 不盲信 libcurl 的默认 CA 路径（MSYS2 下可能是 0 字节文件，见上方说明）
  if (!opts.insecure) {
    const std::string& bundle = ca_bundle_path();
    if (!bundle.empty()) {
      curl_easy_setopt(curl, CURLOPT_CAINFO, bundle.c_str());
      if (opts.verbose) {
        console::write_line(stderr, "[tls] 使用 CA bundle: " + bundle);
      }
    }
  }

  if (!opts.proxy.empty()) {
    const std::string proxy = normalize_proxy(opts.proxy);
    curl_easy_setopt(curl, CURLOPT_PROXY, proxy.c_str());
  }
  for (const auto& [key, value] : opts.headers) {
    request_headers.add(key + ": " + value);
  }
  if (request_headers.list != nullptr) {
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, request_headers.list);
  }

  const CURLcode code = curl_easy_perform(curl);
  if (code != CURLE_OK) {
    std::string detail = error_buffer[0] != '\0' ? error_buffer : curl_easy_strerror(code);
    if (code == CURLE_SSL_CACERT_BADFILE || code == CURLE_PEER_FAILED_VERIFICATION) {
      const std::string& bundle = ca_bundle_path();
      detail += "（HTTPS 证书校验失败：CA 证书包";
      detail += bundle.empty() ? "不可用" : ("='" + bundle + "'");
      detail += "；可用 -k / insecure 跳过校验，或安装并在 CURL_CA_BUNDLE 里指定有效的 ca-bundle.crt）";
    }
    curl_easy_cleanup(curl);
    return fail("请求失败: " + url + " -> " + detail);
  }

  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status);
  char* effective = nullptr;
  if (curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effective) == CURLE_OK &&
      effective != nullptr) {
    response.effective_url = effective;
  }
  char* content_type = nullptr;
  if (curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &content_type) == CURLE_OK &&
      content_type != nullptr) {
    response.content_type = content_type;
  }
  curl_easy_cleanup(curl);

  if (response.status < 200 || response.status >= 300) {
    std::string preview = response.body.substr(0, 160);
    for (char& c : preview) {
      if (c == '\n' || c == '\r' || c == '\t') c = ' ';
    }
    return fail("HTTP " + std::to_string(response.status) + " (GET " + url + ")" +
                (preview.empty() ? std::string() : " 响应片段: " + preview));
  }
  return response;
#elif defined(SUBCONV_HAVE_ANDROID_HTTP)
  // 与上面 libcurl 那条路保持同样的分工：android::http_get() 只负责「把请求发出去」，
  // 非 2xx 算不算失败由这里定 —— 这样两条后端的报错文案、重试行为完全一致。
  auto response = android::http_get(url, opts);
  if (!response) return fail(response.error().message);

  if (response->status < 200 || response->status >= 300) {
    std::string preview = response->body.substr(0, 160);
    for (char& c : preview) {
      if (c == '\n' || c == '\r' || c == '\t') c = ' ';
    }
    return fail("HTTP " + std::to_string(response->status) + " (GET " + url + ")" +
                (preview.empty() ? std::string() : " 响应片段: " + preview));
  }
  return response;
#else
  (void)url;
  (void)opts;
  return fail("本次构建未启用任何 HTTP 后端，无法抓取订阅 URL（请用本地文件，或重新配置构建）");
#endif
}

Result<HttpResponse> http_get_with_retry(const std::string& url, const HttpOptions& opts) {
  const int attempts = std::max(1, opts.retries + 1);
  Error last_error("未知错误");
  for (int attempt = 0; attempt < attempts; ++attempt) {
    auto response = http_get(url, opts);
    if (response) return response;
    last_error = response.error();
    if (attempt + 1 < attempts) {
      // 指数退避：500ms, 1s, 2s ...
      const auto delay = std::chrono::milliseconds(500 * (1 << attempt));
      std::this_thread::sleep_for(delay);
    }
  }
  return fail(std::move(last_error));
}

}  // namespace subconv::fetch
