// Android 后端桥（给 src/fetch/http.cpp 与 src/fetch/certprobe.cpp 用）
//
// 为什么需要它：NDK 既不带 libcurl 也不带 OpenSSL。交叉编译这两样东西（体积大、版本敏感、
// 还要自带 CA bundle）换来的只是一个 GET，不划算。这里改成把「发起请求」交给 Java：
// TLS、重定向、代理、gzip、证书链全部复用 Android 自己的网络栈
// （HttpURLConnection / SSLSocket + 系统信任的 CA）。代价是每次抓取跨一次 JNI，
// 对「转订阅」这种低频、单线程的操作可以忽略。
//
// 与 libcurl 实现的对应关系：
//   fetch::http_get()             <->  android::http_get()
//   fetch::probe_peer_cert_sha256 <->  android::probe_peer_cert_sha256()
// 两者签名、返回的 Result 形态、错误信息风格都保持一致，上层（重试/嗅探/缓存/emit）
// 一行都不用改。
#pragma once

#ifdef SUBCONV_HAVE_ANDROID_HTTP

#include <cstdint>
#include <string>
#include <string_view>

#include <jni.h>

#include "subconv/error.hpp"
#include "subconv/fetch.hpp"

namespace subconv::fetch::android {

/// 由 JNI_OnLoad 调用**一次**，缓存 JavaVM 和 com/subconverter/NetBridge 的全局引用。
///
/// 必须在 Java 线程里调用：`env->FindClass()` 用的是「调用栈上的那个类加载器」，
/// 而服务线程是 C++ 自己 std::thread 出来的 native 线程，栈上没有 Java 帧，
/// 那种地方 FindClass 只能看到系统类加载器，找不到 App 自己的类。
/// 所以类引用在这里就抓好、存成全局引用。
void install(JavaVM* vm, JNIEnv* env) noexcept;

/// install() 是否已经成功过。没成功时下面两个函数直接报错，不会崩。
[[nodiscard]] bool ready() noexcept;

/// 单次 GET，等价于 libcurl 那条路径的 http_get()。
/// 返回的 HttpResponse 里 status 可能是非 2xx（由调用方决定怎么报错），
/// 只有「网络层就失败了」才返回 Error。
[[nodiscard]] Result<HttpResponse> http_get(const std::string& url, const HttpOptions& opts);

/// 对端叶子证书的 SHA-256 指纹（冒号分隔的大写十六进制），
/// 格式与 OpenSSL 实现一致（Xray 的 pinnedPeerCertSha256 / v2rayN 的 pcs 要的就是它）。
[[nodiscard]] Result<std::string> probe_peer_cert_sha256(std::string_view host, uint16_t port,
                                                        std::string_view sni,
                                                        int timeout_seconds);

}  // namespace subconv::fetch::android

#endif  // SUBCONV_HAVE_ANDROID_HTTP
