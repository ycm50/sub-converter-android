package com.subconverter;

import android.content.Context;
import android.util.Log;

/**
 * 内嵌服务的进程内单例。
 *
 * <p>为什么需要一层单例而不是在 Activity 里直接调 {@link NativeServer}：服务是**进程级**的
 * 资源（一个监听套接字 + 一个后台线程），而 Activity 会因为各种原因被销毁重建。
 * 如果每次 onCreate 都 nativeStart，就会反复起停服务，WebView 也跟着白屏重载。
 * 这里保证「一个进程只起一个服务，端口在整个进程生命周期内不变」。
 */
public final class ServerHost {

    private static final String TAG = "subconv";

    /** 监听地址：只绑本机回环。界面是给本机 WebView 看的，没有暴露到局域网的理由。 */
    private static final String LISTEN = "127.0.0.1";

    /** 0 = 让内核分配一个当下空闲的端口（见 {@link NativeServer#nativeStart} 的说明）。 */
    private static final int RANDOM_PORT = 0;

    /** 等上一次停止收尾的上限。正常情况几十毫秒就够。 */
    private static final long STOP_WAIT_MILLIS = 30_000L;

    private static final Object LOCK = new Object();

    private static boolean started;
    private static boolean stopping;
    private static volatile int port = -1;

    private ServerHost() {
    }

    /**
     * 确保服务已启动，返回实际监听的端口。可以重复调用（重建 Activity 时走的就是这条路径）。
     *
     * @throws IllegalStateException 启动失败；message 里带 native 侧给出的原因
     */
    public static int ensureStarted(Context context) {
        synchronized (LOCK) {
            waitForPendingStopLocked();

            if (started && port > 0) {
                return port;
            }

            Context app = context.getApplicationContext();
            // 必须在 nativeStart 之前：native 侧要靠它把 TMPDIR 指到 App 私有目录
            NativeServer.nativeSetRuntimeDirs(app.getCacheDir().getAbsolutePath());

            int bound = NativeServer.nativeStart(LISTEN, RANDOM_PORT);
            if (bound <= 0) {
                String reason = NativeServer.nativeLastError();
                throw new IllegalStateException(
                        "内嵌服务启动失败" + (reason == null || reason.isEmpty() ? "" : "：" + reason));
            }

            port = bound;
            started = true;
            Log.i(TAG, "内嵌 subconv 服务已启动: http://" + LISTEN + ":" + port + "/");
            return port;
        }
    }

    /** WebView 要加载的地址；服务没起来时返回 null。 */
    public static String baseUrl() {
        synchronized (LOCK) {
            return (started && port > 0) ? "http://" + LISTEN + ":" + port + "/" : null;
        }
    }

    /**
     * 停服务。**不会阻塞调用方**，可以放心在 {@code onDestroy()} 里调。
     *
     * <p>为什么不在调用线程里直接停：native 侧的 stop 要 join 服务线程，而服务线程可能正好
     * 卡在一次很慢的订阅抓取里（默认 20 秒超时 × 重试）。让 UI 线程去等会直接 ANR，
     * 所以停的动作扔到后台线程，用 {@link #stopping} 告诉后来者「先别急着重启」。
     */
    public static void stop() {
        synchronized (LOCK) {
            if (!started || stopping) {
                return;
            }
            started = false;
            port = -1;
            stopping = true;
        }

        Thread worker = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    NativeServer.nativeStop();
                    Log.i(TAG, "内嵌 subconv 服务已停止");
                } catch (Throwable error) {
                    Log.e(TAG, "停止内嵌服务失败", error);
                } finally {
                    synchronized (LOCK) {
                        stopping = false;
                        LOCK.notifyAll();
                    }
                }
            }
        }, "subconv-stop");
        worker.start();
    }

    /**
     * 上一次的 stop 还没跑完就等一下：否则 nativeStart 可能拿到一个马上要被拆掉的服务。
     *
     * <p>等不到就**直接失败**，不要硬着头皮往下走。native 侧的 start 是幂等的：如果旧服务
     * 还活着它会直接把旧端口还给你，而这个端口对应的线程正在被关掉 —— 于是 WebView 会加载
     * 到一个刚死掉的服务上，表现为白屏且没有任何看得见的原因。宁可抛异常让界面显示
     * 「启动失败」，也不要进入这种半死状态。
     */
    private static void waitForPendingStopLocked() {
        long deadline = System.currentTimeMillis() + STOP_WAIT_MILLIS;
        while (stopping) {
            long remaining = deadline - System.currentTimeMillis();
            if (remaining <= 0) {
                throw new IllegalStateException(
                        "上一次停止内嵌服务还没收尾（超过 " + STOP_WAIT_MILLIS + " ms），"
                                + "先不启动，避免拿到一个正在被关闭的服务");
            }
            try {
                LOCK.wait(remaining);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("等待上一次停止内嵌服务时被中断", interrupted);
            }
        }
    }
}
