package com.subconverter;

/**
 * 内嵌 subconv HTTP 服务的 Java 门面（libsubconv.so 的 JNI 入口）。
 *
 * <p>这个类就是「App 启动 == {@code subconv serve}」的接口：{@link #nativeStart} 会在后台
 * 线程里跑起上游 {@code subconv::server::run()}，等端口就绪后把**实际端口**返回。
 * 传 {@code port = 0} 时端口由内核分配一个当下空闲的 —— 这样不会和系统里别的进程
 * 抢端口，也不会两台设备/两个实例撞在一起。
 *
 * <p>调用顺序（{@link ServerHost} 已经把这些串好了，正常不用直接用它）：
 * <pre>
 *   nativeSetRuntimeDirs(cacheDir)   // 必须先来一次：告诉 native 侧临时/缓存目录在哪
 *   int port = nativeStart("127.0.0.1", 0)
 *   ...  WebView.loadUrl("http://127.0.0.1:" + port + "/")
 *   nativeStop()                     // Activity 退出时
 * </pre>
 *
 * <p>native 侧的方法名必须和 {@code android/jni_bridge.cpp} 里的 {@code Java_com_subconverter_*}
 * 一一对应；这个方法名约定同时也是 R8 的 keep 规则（见 src/main/keepRules/rules.keep）。
 */
public final class NativeServer {

    static {
        System.loadLibrary("subconv");
    }

    private NativeServer() {
    }

    /** 服务端版本号（等同 CLI 的 {@code subconv --version}）。 */
    public static native String nativeVersion();

    /**
     * 注入运行时目录。必须在 {@link #nativeStart} 之前调用一次。
     *
     * <p>为什么需要：上游的 {@code fs::temp_directory()} 只看 TMPDIR / TEMP / TMP，
     * 都取不到就退到 {@code /tmp} —— 而 Android 上既没有 {@code /tmp}，App 也写不进去。
     * 这里把 TMPDIR 指到 App 私有缓存目录，并把它当作服务端订阅缓存的根。
     */
    public static native void nativeSetRuntimeDirs(String cacheDir);

    /**
     * 启动服务并返回实际监听的端口。
     *
     * @param listen 监听地址；一般传 {@code "127.0.0.1"}（只绑本机，不对外暴露）
     * @param port   端口；传 {@code 0} 表示由系统分配一个空闲端口
     * @return 实际端口（&gt; 0）；失败返回 {@code -1}，原因用 {@link #nativeLastError()} 取
     */
    public static native int nativeStart(String listen, int port);

    /** 停止服务并等待服务线程退出。可重复调用；没启动过时是空操作。 */
    public static native void nativeStop();

    /** 最近一次 {@link #nativeStart} 失败的原因；没有失败过时返回空串。 */
    public static native String nativeLastError();

    /** 服务当前是否在运行。 */
    public static native boolean nativeRunning();
}
