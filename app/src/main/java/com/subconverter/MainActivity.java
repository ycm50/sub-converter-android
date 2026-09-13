package com.subconverter;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.DownloadManager;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.graphics.Insets;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.webkit.ConsoleMessage;
import android.webkit.DownloadListener;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.window.OnBackInvokedCallback;
import android.window.OnBackInvokedDispatcher;

/**
 * App 的唯一个界面：**一个 WebView，没有任何原生控件**。
 *
 * <p>整个 App 的行为就等同于在命令行里跑 {@code subconv serve}，再拿浏览器打开它打印的那个
 * 地址 —— 只不过这里的「浏览器」是 WebView，地址是 {@link ServerHost} 用内核分配的随机端口
 * 拼出来的。页面本身（含 /api/* 接口、subconverter 兼容的 /sub?target=&url=）全部由 C++ 侧
 * 的原服务提供，这个 Activity 只负责生命周期与 WebView 的细节。
 *
 * <p><b>没有布局文件</b>：视图树是直接 {@code setContentView(new WebView(this))} 建起来的，
 * 里面只有 WebView 一个节点。也没有进度条、状态遮罩、「重试」按钮，不弹 Toast ——
 * 启动失败与页面加载失败都只写 logcat（tag {@code subconv}），另外把原因以**纯文本**
 * 塞进这个 WebView：那只是 WebView 的页面内容，不是额外的控件。这么做是因为否则失败时
 * 只剩一块白屏，现场什么线索都没有。
 *
 * <p>顺序很关键：**先起服务拿到端口，再 loadUrl**。端口是随机的，没有任何办法提前知道，
 * 所以必须等 {@link ServerHost#ensureStarted} 返回之后才能加载页面。
 *
 * <p>继承的是 framework 的 {@link Activity}，不是 AppCompat 的 —— 这个 App 一个 AppCompat
 * 特性都不需要，主题也换成了 framework 的 {@code Theme.DeviceDefault.*.NoActionBar}，
 * 因此 appcompat 与 material 两个依赖已经从 {@code build.gradle.kts} 里去掉。
 */
public class MainActivity extends Activity {

    private static final String TAG = "subconv";

    private WebView webView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // 整个界面就是这一个 View：不 inflate 任何布局，直接把它当作 content view。
        // 默认布局参数就是 MATCH_PARENT/MATCH_PARENT（PhoneWindow.setContentView 给的）。
        webView = new WebView(this);
        setContentView(webView);

        configureWebView();
        applySystemBarInsets();
        registerBackHandling();

        // 服务是进程级单例，这里重复调用是幂等的：转屏/重建时会复用同一个端口
        startServerThenLoad();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (webView != null) {
            webView.onResume();
        }
    }

    @Override
    protected void onPause() {
        if (webView != null) {
            webView.onPause();
        }
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        if (isFinishing()) {
            // 只有「真的退出 App」才停服务。转屏、深色模式切换这类重建要复用同一个服务，
            // 否则 WebView 会白屏重载一次。
            ServerHost.stop();
        }
        if (webView != null) {
            // destroy() 前必须先摘掉：还挂在视图树上的 WebView 直接 destroy 会崩
            ViewGroup parent = (ViewGroup) webView.getParent();
            if (parent != null) {
                parent.removeView(webView);
            }
            webView.destroy();
            webView = null;
        }
        super.onDestroy();
    }

    // -----------------------------------------------------------------------
    // 启动服务 → 加载页面
    // -----------------------------------------------------------------------

    private void startServerThenLoad() {
        // 起服务会阻塞到「端口就绪」为止（nativeStart 里等的就是 ready 回调），
        // 放主线程会卡住首帧，所以在自己的线程里做。
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    final int port = ServerHost.ensureStarted(getApplicationContext());
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            load("http://127.0.0.1:" + port + "/");
                        }
                    });
                } catch (final Throwable error) {
                    Log.e(TAG, "启动内嵌服务失败", error);
                    final String detail = describe(error);
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            showMessage(getString(R.string.error_server_failed), detail);
                        }
                    });
                }
            }
        }, "subconv-start").start();
    }

    private void load(String url) {
        Log.i(TAG, "加载 Web UI: " + url);
        // 起服务是在后台线程做的，等回到主线程时 Activity 可能已经被销毁了
        // （onDestroy 里把 webView 置了 null），别再往上摸。
        if (webView == null || isFinishing()) {
            return;
        }
        webView.loadUrl(url);
    }

    /**
     * 把失败原因渲染进那个唯一的 WebView —— 不新增任何控件：页面内容仍然只由 WebView
     * 呈现，只是服务没起来的时候这段「页面」由本地给出。
     */
    private void showMessage(String title, String detail) {
        if (webView == null || isFinishing()) {
            return;
        }
        String html = "<!doctype html><meta name=\"viewport\" "
                + "content=\"width=device-width,initial-scale=1\">"
                + "<pre style=\"white-space:pre-wrap;word-break:break-all;"
                + "margin:16px;font-family:monospace;font-size:13px\">"
                + escapeHtml(title) + "\n\n" + escapeHtml(detail)
                + "</pre>";
        webView.loadDataWithBaseURL(null, html, "text/html", "utf-8", null);
    }

    /** 失败详情可能带引号、尖括号（Java 异常消息里很常见），塞进 HTML 前必须转义。 */
    private static String escapeHtml(String text) {
        StringBuilder out = new StringBuilder(text.length() + 16);
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            switch (ch) {
                case '&': out.append("&amp;"); break;
                case '<': out.append("&lt;"); break;
                case '>': out.append("&gt;"); break;
                case '"': out.append("&quot;"); break;
                case '\'': out.append("&#39;"); break;
                default: out.append(ch);
            }
        }
        return out.toString();
    }

    // -----------------------------------------------------------------------
    // WebView
    // -----------------------------------------------------------------------

    @SuppressLint("SetJavaScriptEnabled")
    private void configureWebView() {
        WebSettings settings = webView.getSettings();
        // Web UI 本身就是一个 JS 应用（fetch /api/convert、渲染规则集列表），必须开 JS
        settings.setJavaScriptEnabled(true);
        // 页面用 localStorage 记住上次的输入与选项
        settings.setDomStorageEnabled(true);
        // 只加载我们自己的回环页面，没有理由让页面读本地文件或内容提供器
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setLoadWithOverviewMode(true);
        settings.setUseWideViewPort(true);

        webView.setWebViewClient(new SubconvWebViewClient());
        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public boolean onConsoleMessage(ConsoleMessage message) {
                // 页面里的 console 输出对排查很有用（原来只能在桌面浏览器里看到）
                Log.i(TAG, "web: " + message.message() + " ("
                        + message.sourceId() + ":" + message.lineNumber() + ")");
                return true;
            }
        });
        webView.setDownloadListener(new SubconvDownloadListener());
        webView.addJavascriptInterface(new DownloadBridge(this), DownloadBridge.JS_NAME);
    }

    /**
     * targetSdk 35+ 起系统强制边到边（edge-to-edge），窗口内容会一直画到状态栏和导航栏底下，
     * 而上游那个页面并没有为此留白 —— 标题会被系统图标和手势条压住。这里把系统栏的高度
     * 变成 WebView 自己的 padding：视图树里仍然只有 WebView 一个节点，只是它自己让开了系统栏。
     *
     * <p>API 35 以下窗口默认就是「避开系统栏」的，此时 DecorView 已经把 insets 消费掉了，
     * 这个回调拿到的是 0，等于什么都不做，不会出现双重留白。
     */
    private void applySystemBarInsets() {
        webView.setOnApplyWindowInsetsListener(new View.OnApplyWindowInsetsListener() {
            @Override
            @SuppressWarnings("deprecation")
            public WindowInsets onApplyWindowInsets(View view, WindowInsets insets) {
                int left;
                int top;
                int right;
                int bottom;
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    Insets bars = insets.getInsets(
                            WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
                    left = bars.left;
                    top = bars.top;
                    right = bars.right;
                    bottom = bars.bottom;
                } else {
                    left = insets.getSystemWindowInsetLeft();
                    top = insets.getSystemWindowInsetTop();
                    right = insets.getSystemWindowInsetRight();
                    bottom = insets.getSystemWindowInsetBottom();
                }
                if (view.getPaddingLeft() != left || view.getPaddingTop() != top
                        || view.getPaddingRight() != right || view.getPaddingBottom() != bottom) {
                    view.setPadding(left, top, right, bottom);
                }
                return insets;
            }
        });
    }

    private final class SubconvWebViewClient extends WebViewClient {

        @Override
        public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
            Uri uri = request.getUrl();
            if (isLoopback(uri)) {
                return false;  // 服务自己的跳转，留在 WebView 里
            }
            // 外部链接（订阅面板、文档）交给系统浏览器：既避免把 App 变成一个万能浏览器，
            // 也保证 addJavascriptInterface 暴露出去的方法只对回环页面可见。
            openExternally(uri);
            return true;
        }

        @Override
        public void onPageFinished(WebView view, String url) {
            // 页面每次加载完都装一次下载钩子（脚本自带幂等标记，重复调用无副作用）
            DownloadBridge.installHook(view);
        }

        @Override
        public void onReceivedError(WebView view, WebResourceRequest request,
                                    WebResourceError error) {
            if (!request.isForMainFrame()) {
                return;  // 子资源（favicon 之类）失败不必关心
            }
            Log.e(TAG, "WebView 加载失败: " + error.getErrorCode() + " "
                    + error.getDescription());
            showMessage(getString(R.string.error_page_failed),
                    String.valueOf(error.getDescription()));
        }
    }

    /** 非 blob 的下载（例如直接点开 /sub?target=... 这种带 Content-Disposition 的接口）。 */
    private final class SubconvDownloadListener implements DownloadListener {
        @Override
        public void onDownloadStart(String url, String userAgent, String contentDisposition,
                                    String mimeType, long contentLength) {
            if (url == null) {
                return;
            }
            if (url.startsWith("blob:")) {
                // blob 走 DownloadBridge 注入的钩子（那边拿得到 Blob 对象本身）；
                // 这里还能看到 blob: 说明钩子没装上，只能记一条日志。
                Log.w(TAG, "收到未被钩子接管的 blob 下载: " + url);
                return;
            }

            try {
                DownloadManager manager = (DownloadManager) getSystemService(DOWNLOAD_SERVICE);
                if (manager == null) {
                    throw new IllegalStateException("系统没有 DownloadManager");
                }
                // 不指定目标目录：DownloadManager 会存进系统「下载」并按响应头命名，
                // 这样不需要任何存储权限
                manager.enqueue(new DownloadManager.Request(Uri.parse(url)));
                Log.i(TAG, "已交给系统下载: " + url);
            } catch (Exception error) {
                // 没有任何界面可以提示，只能留在日志里
                Log.e(TAG, "下载失败: " + url, error);
            }
        }
    }

    // -----------------------------------------------------------------------
    // 返回键
    // -----------------------------------------------------------------------

    /**
     * targetSdk 35+ 起预测性返回默认生效，那时 {@code onBackPressed()} 不再被调用，
     * 必须注册 {@link OnBackInvokedCallback}（API 33+）。两条路都接上，各版本行为一致。
     */
    private void registerBackHandling() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            getOnBackInvokedDispatcher().registerOnBackInvokedCallback(
                    OnBackInvokedDispatcher.PRIORITY_DEFAULT,
                    new OnBackInvokedCallback() {
                        @Override
                        public void onBackInvoked() {
                            handleBack();
                        }
                    });
        }
    }

    /** API 33 以下走这里。 */
    @Override
    @SuppressWarnings("deprecation")
    public void onBackPressed() {
        handleBack();
    }

    private void handleBack() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
            return;
        }
        finish();
    }

    // -----------------------------------------------------------------------
    // 小工具
    // -----------------------------------------------------------------------

    /** 是否是我们自己起的那个回环服务。 */
    private static boolean isLoopback(Uri uri) {
        if (uri == null) {
            return false;
        }
        String scheme = uri.getScheme();
        if (scheme == null || !(scheme.equals("http") || scheme.equals("https"))) {
            return false;
        }
        String host = uri.getHost();
        return "127.0.0.1".equals(host) || "localhost".equals(host) || "::1".equals(host);
    }

    private void openExternally(Uri uri) {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, uri));
        } catch (ActivityNotFoundException error) {
            Log.w(TAG, "没有能打开 " + uri + " 的应用");
        }
    }

    private static String describe(Throwable error) {
        String message = error.getMessage();
        return (message == null || message.isEmpty()) ? error.getClass().getSimpleName() : message;
    }
}
