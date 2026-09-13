// JNI 入口：Android 侧启动/停止内嵌的 subconv HTTP 服务
//
// 这个文件就是「App 启动 == subconv serve」这句话的落地点：
//   Java 调 nativeStart("127.0.0.1", 0)
//     -> C++ 在后台线程跑 subconv::server::run()
//     -> 上游本来就支持 port = 0（系统分配空闲端口），并通过新增的 ReadyHandler 回调
//        把实际端口报回来
//     -> nativeStart 阻塞等到端口就绪后把它返回给 Java
//   Java 拿这个端口去 loadUrl("http://127.0.0.1:<port>/")，就是 WebView 打开自己起的那个页面。
//
// 为什么端口必须「随机可用」而不是写死：写死一个端口就意味着两台 App 抢同一个端口、
// 或者撞上系统里别的进程；port = 0 由内核挑一个当下空闲的，天然不会冲突。
//
// 线程与生命周期：
//   * 服务跑在 C++ 的 std::thread 上（不是 Java 线程），所以抓订阅时的 JNI 调用
//     需要先 AttachCurrentThread —— 这件事在 src/fetch/android_http.cpp 里处理。
//   * nativeStop() 通过 server::request_stop() 让 accept 循环退出并 join 线程，
//     保证 Activity 销毁后不留下野服务。
#include <jni.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <mutex>
#include <string>
#include <thread>

#include "subconv/console.hpp"
#include "subconv/fsutil.hpp"
#include "subconv/server.hpp"

#ifdef SUBCONV_HAVE_ANDROID_HTTP
#include "subconv/android_http.hpp"
#endif

namespace {

// ---------------------------------------------------------------------------
// 进程内的服务状态。只有一个服务实例（App 也只需要一个）。
//
// g_worker 为什么是裸指针而不是 std::thread 对象：std::thread 的析构函数在「仍然
// joinable」时会调 std::terminate()。而本进程退出时并不保证已经 join 过 —— 用户从最近任务
// 里划掉 App 时 onDestroy 不一定跑，系统也可能直接结束进程。放到堆上之后，退出路径上
// 根本没有它会去跑的析构函数，最坏情况只是泄漏一个 thread 对象，比在退出时 abort 好得多。
//（g_worker 只在持有 g_mutex 时读写。）
// ---------------------------------------------------------------------------
std::mutex g_mutex;
std::condition_variable g_ready_cv;

std::thread* g_worker = nullptr;
int g_bound_port = -1;     ///< 实际监听端口；> 0 表示服务可用
bool g_signalled = false;  ///< 服务线程已经有结论（起来了，或失败退出了）
bool g_finished = false;   ///< 服务线程已经结束
std::string g_last_error;  ///< 最近一次失败原因（给 nativeLastError）
std::string g_cache_dir;   ///< App 私有缓存目录（nativeSetRuntimeDirs 注入）
std::atomic<bool> g_running{false};

/// 把服务线程对象从全局摘下来（调用方负责 join + delete）。必须在持有 g_mutex 时调用。
std::thread* detach_worker_locked() {
  std::thread* worker = g_worker;
  g_worker = nullptr;
  return worker;
}

/// join 并释放一个已经摘下来的线程对象。
void retire_worker(std::thread* worker) {
  if (worker == nullptr) return;
  if (worker->joinable()) {
    if (worker->get_id() == std::this_thread::get_id()) {
      // 正常到不了这里（nativeStart/nativeStop 都是 Java 线程调的）。真要到了也只能 detach：
      // join 自己会死锁，而 delete 一个 joinable 的 std::thread 会直接 std::terminate。
      worker->detach();
    } else {
      worker->join();
    }
  }
  delete worker;
}

std::string jstring_to_utf8(JNIEnv* env, jstring value) {
  if (value == nullptr) return {};
  const char* chars = env->GetStringUTFChars(value, nullptr);
  if (chars == nullptr) return {};
  std::string out(chars);
  env->ReleaseStringUTFChars(value, chars);
  return out;
}

/// 服务线程主体。run() 会一直阻塞到 request_stop()，所以这里的收尾就是正常的停止路径。
void worker_main(const subconv::server::ServerOptions& opts) {
  auto served = subconv::server::run(opts, [](const std::string& /*url*/, int port) {
    // 监听成功、端口已定 —— 赶紧把 nativeStart 叫醒
    std::lock_guard<std::mutex> guard(g_mutex);
    g_bound_port = port;
    g_signalled = true;
    g_ready_cv.notify_all();
  });

  std::string failure;
  {
    std::lock_guard<std::mutex> guard(g_mutex);
    if (!served) {
      failure = served.error().message;
      g_last_error = failure;
    }
    g_running.store(false, std::memory_order_relaxed);
    g_finished = true;
    // 失败时 g_bound_port 仍然是 -1；这里也把 g_signalled 立起来，
    // 免得 nativeStart 白白等到 15 秒超时。
    g_signalled = true;
    g_ready_cv.notify_all();
  }
  if (!failure.empty()) {
    subconv::console::write_line(stderr, "内嵌服务退出: " + failure);
  }
}

}  // namespace

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
  JNIEnv* env = nullptr;
  if (vm == nullptr || vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK ||
      env == nullptr) {
    return JNI_ERR;
  }

#ifdef SUBCONV_HAVE_ANDROID_HTTP
  // 在这里（Java 线程）把 NetBridge 的类引用抓好，服务线程才能用它发请求 ——
  // 详见 src/fetch/android_http.cpp 文件头的第 1 条。
  subconv::fetch::android::install(vm, env);
#endif

  return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_subconverter_NativeServer_nativeVersion(JNIEnv* env, jclass /*clazz*/) {
#ifdef SUBCONV_VERSION
  return env->NewStringUTF(SUBCONV_VERSION);
#else
  return env->NewStringUTF("dev");
#endif
}

extern "C" JNIEXPORT void JNICALL
Java_com_subconverter_NativeServer_nativeSetRuntimeDirs(JNIEnv* env, jclass /*clazz*/,
                                                        jstring j_cache_dir) {
  const std::string cache_dir = jstring_to_utf8(env, j_cache_dir);

  {
    std::lock_guard<std::mutex> guard(g_mutex);
    g_cache_dir = cache_dir;
  }

  // 上游的 fs::temp_directory() 只看 TMPDIR / TEMP / TMP，都没有就退到 "/tmp" ——
  // Android 上没有 /tmp 这个目录（App 也没有写它的权限）。把 TMPDIR 指到应用私有的
  // 缓存目录，任何「默认落到临时目录」的行为才不会写到一个不存在的地方。
  if (!cache_dir.empty()) {
    ::setenv("TMPDIR", cache_dir.c_str(), 1);
  }
}

extern "C" JNIEXPORT jint JNICALL
Java_com_subconverter_NativeServer_nativeStart(JNIEnv* env, jclass /*clazz*/, jstring j_listen,
                                              jint j_port) {
  const std::string listen = jstring_to_utf8(env, j_listen);
  const int requested_port = static_cast<int>(j_port);

  std::string cache_dir;
  std::thread* stale = nullptr;
  {
    std::lock_guard<std::mutex> guard(g_mutex);
    // 幂等：已经在跑就把现有端口还回去（Activity 重建时不用重开服务）
    if (g_running.load(std::memory_order_relaxed) && g_bound_port > 0) {
      return static_cast<jint>(g_bound_port);
    }
    stale = detach_worker_locked();  // 上一轮的线程对象，回收掉
    cache_dir = g_cache_dir;
  }
  retire_worker(stale);

  subconv::server::ServerOptions opts;
  opts.listen = listen.empty() ? std::string("127.0.0.1") : listen;
  opts.port = requested_port;  // 0 = 由系统分配一个当下空闲的端口
  opts.open_browser = false;   // App 里由 WebView 负责显示，不需要（也不该）去开系统浏览器
  opts.verbose = false;
  if (!cache_dir.empty()) {
    // 订阅抓取的磁盘缓存放进 App 私有目录：Android 上进程随时可能被杀，
    // 放私有目录不占用户可见空间，也不会因为外部存储权限问题失败。
    opts.load.cache_dir = subconv::fs::join(cache_dir, "subconv-cache");
    opts.load.cache_ttl_seconds = 300;
  }

  std::unique_lock<std::mutex> lock(g_mutex);
  g_bound_port = -1;
  g_signalled = false;
  g_finished = false;
  g_last_error.clear();
  g_running.store(true, std::memory_order_relaxed);
  g_worker = new std::thread([opts]() { worker_main(opts); });

  // 等「起来了」或「已经失败退出」。15 秒是给「绑定端口失败」这类瞬时失败的余量，
  // 正常情况下一两毫秒就会返回。
  g_ready_cv.wait_for(lock, std::chrono::seconds(15), [] { return g_signalled; });

  if (g_bound_port > 0) {
    return static_cast<jint>(g_bound_port);
  }

  // --- 走到这里就是启动失败 ---
  const bool still_running = !g_finished;
  if (g_last_error.empty()) {
    g_last_error = still_running ? "启动内嵌 HTTP 服务超时（15 秒内没有拿到端口）"
                                 : "内嵌 HTTP 服务在启动过程中就退出了";
  }
  lock.unlock();

  if (still_running) {
    // 线程还卡在某处：先叫停再回收，别给 App 留一个跑着的服务
    subconv::server::request_stop();
    std::thread* dead = nullptr;
    {
      std::lock_guard<std::mutex> guard(g_mutex);
      dead = detach_worker_locked();
    }
    retire_worker(dead);
  }

  return -1;
}

extern "C" JNIEXPORT void JNICALL Java_com_subconverter_NativeServer_nativeStop(JNIEnv* /*env*/,
                                                                               jclass /*clazz*/) {
  {
    std::lock_guard<std::mutex> guard(g_mutex);
    if (g_worker == nullptr) return;  // 没启动过 / 已经停过：空操作
  }

  // 让 run() 的 accept 循环退出（服务里已经备好 shutdown + poll 超时两条路）
  subconv::server::request_stop();

  std::thread* worker = nullptr;
  {
    std::lock_guard<std::mutex> guard(g_mutex);
    worker = detach_worker_locked();
  }
  retire_worker(worker);

  std::lock_guard<std::mutex> guard(g_mutex);
  g_running.store(false, std::memory_order_relaxed);
  g_bound_port = -1;
  g_signalled = false;
  g_finished = true;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_subconverter_NativeServer_nativeLastError(JNIEnv* env, jclass /*clazz*/) {
  std::lock_guard<std::mutex> guard(g_mutex);
  return env->NewStringUTF(g_last_error.c_str());
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_subconverter_NativeServer_nativeRunning(JNIEnv* /*env*/, jclass /*clazz*/) {
  return g_running.load(std::memory_order_relaxed) ? JNI_TRUE : JNI_FALSE;
}
