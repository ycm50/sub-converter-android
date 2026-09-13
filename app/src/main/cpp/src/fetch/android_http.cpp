// Android 后端桥：C++ 侧的抓取 / 证书探测 → Java 的 HttpURLConnection / SSLSocket
//
// 这个文件是整份移植里唯一「为了 Android 而新写」的网络代码。它实现了
// android_http.hpp 里声明的三个入口，被 src/fetch/http.cpp 与 src/fetch/certprobe.cpp
// 以「另一种后端」的方式调用（那两处的改动只是补了一个 #elif 分支）。
//
// 三个必须小心的 JNI 细节（都在下面有实现，这里先说明为什么）：
//
//   1. 类引用要提前抓好。服务线程是 C++ 自己 std::thread 出来的 native 线程，栈上没有
//      Java 帧，那种地方 FindClass() 只能看到系统类加载器 —— 找不到 App 自己的类。
//      所以 install() 在 JNI_OnLoad（Java 线程）里就把 NetBridge 抓成全局引用。
//   2. native 线程必须显式 Attach。服务线程不在 JVM 里，得 AttachCurrentThread 才拿得到
//      JNIEnv；线程退出时再 Detach，否则 JVM 会认为这个线程还活着（还会拖住 JVM 卸载）。
//   3. 局部引用必须手动开帧。局部引用本来是 native 方法返回时自动释放的，而服务线程
//      永远不会「返回 Java」，于是不显式 PushLocalFrame/PopLocalFrame 就会一路泄漏到 512
//      上限然后 JNI 直接报错。
#include "subconv/android_http.hpp"

#ifdef SUBCONV_HAVE_ANDROID_HTTP

#include <map>
#include <string>
#include <string_view>
#include <utility>

#include "subconv/codec.hpp"
#include "subconv/json.hpp"

namespace subconv::fetch::android {
namespace {

// 与 Java 侧 com/subconverter/NetBridge 一一对应；改签名必须两边一起改。
constexpr const char* kBridgeClass = "com/subconverter/NetBridge";
constexpr const char* kGetName = "get";
constexpr const char* kGetSignature =
    "(Ljava/lang/String;Ljava/lang/String;JJZZLjava/lang/String;"
    "[Ljava/lang/String;[Ljava/lang/String;)Ljava/lang/String;";
constexpr const char* kProbeName = "peerCertSha256";
constexpr const char* kProbeSignature = "(Ljava/lang/String;ILjava/lang/String;I)Ljava/lang/String;";

JavaVM* g_vm = nullptr;
jclass g_bridge = nullptr;
jmethodID g_get = nullptr;
jmethodID g_probe = nullptr;

/// 当前线程的 JNIEnv。
///
/// JVM 里的线程（比如调用 nativeStart 的那个）本来就是 attached，直接用；
/// C++ 起的服务线程需要先 Attach。thread_local 的析构负责 Detach，
/// 所以「谁挂上去的谁摘下来」，不会去 Detach 那些本来就属于 JVM 的线程。
struct EnvScope {
  JNIEnv* env = nullptr;
  bool attached = false;

  EnvScope() {
    if (g_vm == nullptr) return;
    void* raw = nullptr;
    const jint status = g_vm->GetEnv(&raw, JNI_VERSION_1_6);
    if (status == JNI_OK) {
      env = static_cast<JNIEnv*>(raw);
      return;
    }
    if (status == JNI_EDETACHED && g_vm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
      attached = true;
      return;
    }
    env = nullptr;
  }

  ~EnvScope() {
    if (attached && g_vm != nullptr) g_vm->DetachCurrentThread();
  }

  EnvScope(const EnvScope&) = delete;
  EnvScope& operator=(const EnvScope&) = delete;
};

JNIEnv* env_for_this_thread() {
  thread_local EnvScope scope;
  return scope.env;
}

/// 一次 JNI 调用期间的局部引用作用域。见文件头的第 3 条。
struct LocalFrame {
  JNIEnv* env = nullptr;
  bool active = false;

  LocalFrame(JNIEnv* e, jint capacity) : env(e), active(e != nullptr && e->PushLocalFrame(capacity) == 0) {}
  ~LocalFrame() {
    if (active) env->PopLocalFrame(nullptr);
  }

  LocalFrame(const LocalFrame&) = delete;
  LocalFrame& operator=(const LocalFrame&) = delete;

  [[nodiscard]] bool ok() const noexcept { return active; }
};

/// 把挂起的 Java 异常取出来变成一句可读的话，并且**清掉**它。
/// 不清的话下一次 JNI 调用会带着这个异常进去，行为完全不可预测。
std::string take_exception(JNIEnv* env) {
  if (env == nullptr || !env->ExceptionCheck()) return {};

  jthrowable thrown = env->ExceptionOccurred();
  env->ExceptionClear();

  std::string detail = "Java 侧抛出异常（无详细信息）";
  if (thrown == nullptr) return detail;

  jclass cls = env->GetObjectClass(thrown);
  if (cls != nullptr) {
    const jmethodID to_string = env->GetMethodID(cls, "toString", "()Ljava/lang/String;");
    if (to_string != nullptr) {
      auto text = static_cast<jstring>(env->CallObjectMethod(thrown, to_string));
      if (!env->ExceptionCheck() && text != nullptr) {
        const char* chars = env->GetStringUTFChars(text, nullptr);
        if (chars != nullptr) {
          detail = chars;
          env->ReleaseStringUTFChars(text, chars);
        }
        env->DeleteLocalRef(text);
      }
    }
    env->DeleteLocalRef(cls);
  }
  env->ExceptionClear();
  env->DeleteLocalRef(thrown);
  return detail;
}

/// jstring → std::string。
///
/// 注意 GetStringUTFChars 给的是 JNI 的「modified UTF-8」：BMP 内的字符（中文、
/// 日文、韩文、绝大多数符号）与 UTF-8 逐字节相同，只有 U+10000 以上（emoji）会被
/// 编成代理对（CESU-8）。这里不在乎那种情况：走这条路的只有 URL、Content-Type、
/// 响应头，还有异常消息；订阅正文是 base64 过的，绕开了这个问题。
std::string jstring_to_utf8(JNIEnv* env, jstring value) {
  if (value == nullptr) return {};
  const char* chars = env->GetStringUTFChars(value, nullptr);
  if (chars == nullptr) {
    // 只有 OOM 会走到这里，而且此时 env 上挂着一个 OutOfMemoryError。
    // 不清掉的话，异常会跨过 PopLocalFrame 一直挂在这个（长期存活的服务）线程上，
    // 污染后面每一次 JNI 调用 —— 那才是真正难查的问题。
    env->ExceptionClear();
    return {};
  }
  std::string out(chars);
  env->ReleaseStringUTFChars(value, chars);
  return out;
}

/// 构造 std::string[] 形式的 jstring 数组（两个并行数组：名字、值）。
/// 失败返回 false，调用方负责报错（异常已经挂在 env 上）。
bool make_string_arrays(JNIEnv* env, const std::map<std::string, std::string>& headers,
                        jobjectArray& names, jobjectArray& values) {
  const jsize count = static_cast<jsize>(headers.size());
  jclass string_class = env->FindClass("java/lang/String");
  if (string_class == nullptr) return false;

  if (count > 0) {
    names = env->NewObjectArray(count, string_class, nullptr);
    values = env->NewObjectArray(count, string_class, nullptr);
    if (names == nullptr || values == nullptr) return false;
  } else {
    // 空数组也要给：Java 侧按 length 遍历，null 会 NPE。0 长度数组用 0 元素创建即可。
    names = env->NewObjectArray(0, string_class, nullptr);
    values = env->NewObjectArray(0, string_class, nullptr);
    if (names == nullptr || values == nullptr) return false;
  }

  jsize index = 0;
  for (const auto& [name, value] : headers) {
    jstring j_name = env->NewStringUTF(name.c_str());
    jstring j_value = env->NewStringUTF(value.c_str());
    if (j_name == nullptr || j_value == nullptr) return false;
    env->SetObjectArrayElement(names, index, j_name);
    env->SetObjectArrayElement(values, index, j_value);
    env->DeleteLocalRef(j_name);
    env->DeleteLocalRef(j_value);
    ++index;
  }
  return true;
}

}  // namespace

void install(JavaVM* vm, JNIEnv* env) noexcept {
  g_vm = vm;
  if (env == nullptr || vm == nullptr) return;

  // FindClass 必须在这个（Java）线程上做，见文件头第 1 条
  jclass local = env->FindClass(kBridgeClass);
  if (local == nullptr) {
    // 找不到就把异常清掉：让上层以「桥不可用」的形式报错，
    // 而不是把一个挂起的异常留在 JNI 状态里，污染后面所有调用。
    env->ExceptionClear();
    return;
  }

  g_bridge = static_cast<jclass>(env->NewGlobalRef(local));
  env->DeleteLocalRef(local);
  if (g_bridge == nullptr) {
    env->ExceptionClear();
    return;
  }

  g_get = env->GetStaticMethodID(g_bridge, kGetName, kGetSignature);
  if (g_get == nullptr) env->ExceptionClear();

  g_probe = env->GetStaticMethodID(g_bridge, kProbeName, kProbeSignature);
  if (g_probe == nullptr) env->ExceptionClear();
}

bool ready() noexcept {
  return g_vm != nullptr && g_bridge != nullptr && g_get != nullptr;
}

Result<HttpResponse> http_get(const std::string& url, const HttpOptions& opts) {
  if (!ready()) {
    return fail("Android 网络桥未就绪（JNI_OnLoad 未执行或 NetBridge 缺失），无法抓取订阅 URL");
  }

  JNIEnv* env = env_for_this_thread();
  if (env == nullptr) return fail("无法附着到 Java 虚拟机，抓取订阅失败");

  // 局部引用帧的容量按请求头数量给足：每个头会临时产生 2 个 jstring + 2 个数组元素引用，
  // 帧太小的话 JVM 会在分配新局部引用时失败（PopLocalFrame 还得照常配对）。
  LocalFrame frame(env, static_cast<jint>(16 + 4 * opts.headers.size()));
  if (!frame.ok()) return fail("JNI 局部引用帧分配失败：" + take_exception(env));

  jstring j_url = env->NewStringUTF(url.c_str());
  jstring j_user_agent = env->NewStringUTF(opts.user_agent.c_str());
  jstring j_proxy = opts.proxy.empty() ? nullptr : env->NewStringUTF(opts.proxy.c_str());
  if (j_url == nullptr || j_user_agent == nullptr || (!opts.proxy.empty() && j_proxy == nullptr)) {
    return fail("构造 JNI 字符串失败：" + take_exception(env));
  }

  jobjectArray header_names = nullptr;
  jobjectArray header_values = nullptr;
  if (!make_string_arrays(env, opts.headers, header_names, header_values)) {
    return fail("构造请求头数组失败：" + take_exception(env));
  }

  auto payload = static_cast<jstring>(env->CallStaticObjectMethod(
      g_bridge, g_get, j_url, j_user_agent,
      static_cast<jlong>(opts.timeout_seconds),
      static_cast<jlong>(opts.connect_timeout_seconds),
      static_cast<jboolean>(opts.follow_redirects ? JNI_TRUE : JNI_FALSE),
      static_cast<jboolean>(opts.insecure ? JNI_TRUE : JNI_FALSE),
      j_proxy, header_names, header_values));

  if (env->ExceptionCheck()) {
    return fail("抓取订阅失败: " + url + " -> " + take_exception(env));
  }
  if (payload == nullptr) {
    return fail("抓取订阅失败: " + url + " -> Java 侧没有返回内容");
  }

  const std::string text = jstring_to_utf8(env, payload);
  Json document = Json::parse(text, nullptr, /*allow_exceptions=*/false);
  if (document.is_discarded() || !document.is_object()) {
    return fail("抓取订阅失败: " + url + " -> Java 侧返回的内容不是合法 JSON");
  }
  if (document.contains("error") && document["error"].is_string()) {
    return fail("抓取订阅失败: " + url + " -> " + document["error"].get<std::string>());
  }

  HttpResponse response;
  response.status = document.value("status", 0L);
  response.effective_url = document.value("effectiveUrl", std::string());
  response.content_type = document.value("contentType", std::string());

  // 正文走 base64：订阅文本里有中文、emoji、有时还有二进制残留，
  // 用 jstring 传会在 modified UTF-8 上出问题，base64 是唯一稳的形态。
  const std::string body_base64 = document.value("bodyBase64", std::string());
  if (!body_base64.empty()) {
    auto decoded = codec::base64_decode(body_base64);
    if (!decoded) {
      return fail("抓取订阅失败: " + url + " -> 响应体解码失败: " + decoded.error().message);
    }
    response.body = std::move(*decoded);
  }

  if (document.contains("headers") && document["headers"].is_object()) {
    const Json& headers = document["headers"];
    for (auto it = headers.begin(); it != headers.end(); ++it) {
      if (it.value().is_string()) {
        response.headers[codec::to_lower(it.key())] = it.value().get<std::string>();
      }
    }
  }

  return response;
}

Result<std::string> probe_peer_cert_sha256(std::string_view host, uint16_t port,
                                          std::string_view sni, int timeout_seconds) {
  if (host.empty() || port == 0) return fail("探测证书需要合法的 host:port");

  const std::string where = std::string(host) + ":" + std::to_string(port);
  if (g_vm == nullptr || g_bridge == nullptr || g_probe == nullptr) {
    return fail("Android 证书探测桥未就绪，无法探测 " + where);
  }

  JNIEnv* env = env_for_this_thread();
  if (env == nullptr) return fail("无法附着到 Java 虚拟机，证书探测失败");

  LocalFrame frame(env, 16);
  if (!frame.ok()) return fail("JNI 局部引用帧分配失败：" + take_exception(env));

  const std::string host_text(host);
  jstring j_host = env->NewStringUTF(host_text.c_str());
  // sni 为空时传 null，让 Java 侧按「用 host」处理（与 OpenSSL 实现一致）
  jstring j_sni = sni.empty() ? nullptr : env->NewStringUTF(std::string(sni).c_str());
  if (j_host == nullptr || (!sni.empty() && j_sni == nullptr)) {
    return fail("构造 JNI 字符串失败：" + take_exception(env));
  }

  const jint effective_timeout = static_cast<jint>(timeout_seconds > 0 ? timeout_seconds : 5);
  auto result = static_cast<jstring>(env->CallStaticObjectMethod(
      g_bridge, g_probe, j_host, static_cast<jint>(port), j_sni, effective_timeout));

  if (env->ExceptionCheck()) {
    return fail("TLS 握手或取证书失败（" + where + "）：" + take_exception(env));
  }
  if (result == nullptr) {
    return fail("对端没有提供证书（" + where + "）");
  }

  const std::string fingerprint = jstring_to_utf8(env, result);
  if (fingerprint.empty()) return fail("对端证书指纹为空（" + where + "）");
  return fingerprint;
}

}  // namespace subconv::fetch::android

#endif  // SUBCONV_HAVE_ANDROID_HTTP
