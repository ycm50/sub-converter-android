package com.subconverter;

import android.content.ContentValues;
import android.content.Context;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.MediaStore;
import android.util.Log;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * 让 Web UI 的「下载」按钮真的能存文件。
 *
 * <p>Web UI 是这么导出的（data/web/index.html）：
 * <pre>
 *   var blob = new Blob([config]);
 *   var url  = URL.createObjectURL(blob);
 *   var link = document.createElement("a");
 *   link.href = url; link.download = filename; link.click();
 *   setTimeout(function () { URL.revokeObjectURL(url); }, 0);
 * </pre>
 *
 * <p>在 WebView 里这条链断在两处：
 * <ol>
 *   <li>{@code blob:} URL 是渲染进程内部的东西，原生侧（DownloadListener）拿到的只是一个
 *       没法读取的字符串；</li>
 *   <li>而且这个页面**立刻**就把 URL revoke 了，任何「先拿到 URL 再回头去 fetch」的做法
 *       都会踩到竞态。</li>
 * </ol>
 *
 * <p>所以这里换一个切入点：注入一段脚本，把 {@code URL.createObjectURL} 包一层，
 * 记住「URL → Blob 对象」的对应关系。等到下载的链接被点击时，我们直接拿到那个 Blob 对象
 * —— revoke 与否都不影响已经持有的 Blob —— 用 FileReader 读成文本，再通过
 * {@link #saveText} 交回 Java 落盘。
 *
 * <p>顺带一个好处：走的是 JS 字符串而不是字节流，中文和 emoji 全程是 UTF-16，
 * 不会碰上 JNI modified UTF-8 的坑。
 *
 * <p>安全边界：{@code addJavascriptInterface} 会把这些方法暴露给页面里的**所有** JS，
 * 所以 WebView 必须只加载我们自己的回环页面 —— MainActivity 的
 * {@code shouldOverrideUrlLoading} 负责把外部链接丢给系统浏览器。
 */
final class DownloadBridge {

    private static final String TAG = "subconv";

    /** JS 侧访问它的名字：{@code SubconvDownload.saveText(name, text)}。 */
    static final String JS_NAME = "SubconvDownload";

    /** 没拿到文件名时的兜底。 */
    private static final String FALLBACK_NAME = "config.txt";

    /**
     * 注入到页面里的钩子。要点：
     * <ul>
     *   <li>{@code URL.createObjectURL} 被包一层，记下 Blob 对象 —— 这样不依赖
     *       revoke 的时机；</li>
     *   <li>用**捕获阶段**的 document 监听：页面是 {@code link.click()} 合成点击，
     *       捕获阶段一样会先收到，而且此时 {@code link.download} 已经设好了；</li>
     *   <li>找不到对应的 Blob（普通 http 链接等）就什么都不做，让默认行为继续，
     *       那种情况由 MainActivity 的 DownloadListener 处理；</li>
     *   <li>用全局标记防止页面内导航后重复安装（onPageFinished 每次都会调）。</li>
     * </ul>
     */
    static final String INTERCEPT_SCRIPT =
            "(function(){"
                    + "  if (window.__subconvDownloadHooked) { return; }"
                    + "  window.__subconvDownloadHooked = true;"
                    + "  var blobs = new Map();"
                    + "  var originalCreate = URL.createObjectURL;"
                    + "  URL.createObjectURL = function(obj){"
                    + "    var url = originalCreate.call(URL, obj);"
                    + "    try { blobs.set(url, obj); } catch (e) {}"
                    + "    return url;"
                    + "  };"
                    + "  document.addEventListener('click', function(event){"
                    + "    var node = event.target;"
                    + "    var link = null;"
                    + "    while (node && node !== document) {"
                    + "      if (node.tagName === 'A' && node.hasAttribute &&"
                    + "          node.hasAttribute('download')) { link = node; break; }"
                    + "      node = node.parentNode;"
                    + "    }"
                    + "    if (!link) { return; }"
                    + "    var href = link.getAttribute('href') || '';"
                    + "    var blob = blobs.get(href) || blobs.get(link.href);"
                    + "    if (!blob) { return; }"
                    + "    event.preventDefault();"
                    + "    event.stopImmediatePropagation();"
                    + "    var name = link.getAttribute('download') || '';"
                    + "    var reader = new FileReader();"
                    + "    reader.onload = function(){"
                    + "      window." + JS_NAME + ".saveText(name, String(reader.result));"
                    + "    };"
                    + "    reader.onerror = function(){"
                    + "      window." + JS_NAME + ".failed('读取 Blob 失败');"
                    + "    };"
                    + "    reader.readAsText(blob);"
                    + "  }, true);"
                    + "})()";

    private final Context context;

    DownloadBridge(Context context) {
        this.context = context.getApplicationContext();
    }

    /** 在页面加载完成后安装钩子。页面内导航后会重新安装（脚本自带幂等标记）。 */
    static void installHook(WebView webView) {
        webView.evaluateJavascript(INTERCEPT_SCRIPT, null);
    }

    /**
     * 页面把 Blob 内容交回来的入口。
     *
     * <p>注意这是 WebView 的 JavaBridge 线程在调用，不是主线程 —— 这里只做文件 I/O 和
     * 日志，不碰任何界面，所以不需要再切回主线程。
     */
    @JavascriptInterface
    public void saveText(String fileName, String text) {
        String name = sanitize(fileName);
        try {
            write(name, (text == null ? "" : text).getBytes(StandardCharsets.UTF_8));
        } catch (Exception error) {
            // 这个 App 没有任何界面可以提示，失败只留在日志里
            Log.e(TAG, "保存下载文件失败", error);
        }
    }

    /** 页面侧读取 Blob 失败时的上报入口（同样来自 JavaBridge 线程）。 */
    @JavascriptInterface
    public void failed(String message) {
        Log.w(TAG, "页面读取 Blob 失败: " + message);
    }

    // -----------------------------------------------------------------------
    // 落盘
    // -----------------------------------------------------------------------

    private void write(String name, byte[] data) throws IOException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            writeToMediaStore(name, data);
        } else {
            writeToAppExternalFiles(name, data);
        }
    }

    /** API 29+：塞进系统「下载」目录。走 MediaStore 不需要任何存储权限。 */
    private void writeToMediaStore(String name, byte[] data) throws IOException {
        ContentValues values = new ContentValues();
        values.put(MediaStore.Downloads.DISPLAY_NAME, name);
        values.put(MediaStore.Downloads.MIME_TYPE, "text/plain");
        values.put(MediaStore.Downloads.IS_PENDING, 1);

        Uri item = context.getContentResolver()
                .insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values);
        if (item == null) {
            throw new IOException("无法在「下载」目录里创建文件");
        }
        try {
            OutputStream out = context.getContentResolver().openOutputStream(item);
            if (out == null) {
                throw new IOException("无法打开输出流");
            }
            try {
                out.write(data);
            } finally {
                out.close();
            }
        } catch (IOException error) {
            context.getContentResolver().delete(item, null, null);  // 别留半个空文件
            throw error;
        }

        values.clear();
        values.put(MediaStore.Downloads.IS_PENDING, 0);
        context.getContentResolver().update(item, values, null, null);
        Log.i(TAG, "已保存到系统「下载」目录：" + name);
    }

    /**
     * API 24-28：公共「下载」目录要 WRITE_EXTERNAL_STORAGE（还是运行时权限），
     * 为了一个导出按钮去要存储权限不划算，所以退到 App 自己的外部目录 ——
     * 不需要任何权限，用文件管理器也找得到。
     */
    private void writeToAppExternalFiles(String name, byte[] data) throws IOException {
        File dir = context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS);
        if (dir == null) {
            dir = new File(context.getFilesDir(), "downloads");
        }
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IOException("无法创建目录 " + dir.getAbsolutePath());
        }
        File target = new File(dir, name);
        try (OutputStream out = new FileOutputStream(target)) {
            out.write(data);
        }
        Log.i(TAG, "已保存到：" + target.getAbsolutePath());
    }

    /** 文件名是从页面来的，不能直接当路径用：去掉路径分隔符和控制字符。 */
    private static String sanitize(String fileName) {
        String name = (fileName == null) ? "" : fileName.trim();
        StringBuilder builder = new StringBuilder(name.length());
        for (int i = 0; i < name.length(); i++) {
            char ch = name.charAt(i);
            boolean bad = ch == '/' || ch == '\\' || ch == ':' || ch == '*' || ch == '?'
                    || ch == '"' || ch == '<' || ch == '>' || ch == '|' || ch < 0x20;
            builder.append(bad ? '_' : ch);
        }
        String cleaned = builder.toString().trim();
        // "." / ".." 这类名字会指到目录本身，直接换掉
        if (cleaned.isEmpty() || cleaned.equals(".") || cleaned.equals("..")) {
            return FALLBACK_NAME;
        }
        return cleaned;
    }

}
