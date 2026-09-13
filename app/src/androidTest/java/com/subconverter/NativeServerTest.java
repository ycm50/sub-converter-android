package com.subconverter;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * 这个移植的核心断言：**App 起来就等于 {@code subconv serve}**。
 *
 * <p>具体验三件事，任何一件坏了 App 都是白屏：
 * <ol>
 *   <li>{@code libsubconv.so} 能被加载（JNI 名字没写错、keep 规则没漏）；</li>
 *   <li>服务能在内核分配的随机端口上起来（{@code port = 0} 这条路径真的通）；</li>
 *   <li>那个端口上真的吐得出 Web UI 与 /api/version（端口报错位了的话这里就会挂）。</li>
 * </ol>
 *
 * <p>这些测试方法跑在 instrumentation 线程上（不是 App 主线程），所以可以直接做网络 IO。
 */
@RunWith(AndroidJUnit4.class)
public class NativeServerTest {

    @After
    public void tearDown() {
        ServerHost.stop();
    }

    @Test
    public void startsOnAnEphemeralPortAndStaysPut() {
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();

        int port = ServerHost.ensureStarted(context);
        assertTrue("端口应当是合法的 TCP 端口，实际 " + port, port > 0 && port <= 65535);

        // 端口是随机分配的，不该是上游 CLI 的默认值 —— 那种「写死端口」的退路一旦回来，
        // 这个断言会立刻抓住（同时也说明内核确实替我们挑了端口）。
        assertTrue("端口看起来是写死的而不是系统分配的：" + port, port != 25500);

        // 幂等：重复调用必须复用同一个服务，否则 Activity 重建一次就会多起一个
        assertEquals(port, ServerHost.ensureStarted(context));
        assertEquals("http://127.0.0.1:" + port + "/", ServerHost.baseUrl());
    }

    @Test
    public void servesWebUiAndApi() throws Exception {
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        int port = ServerHost.ensureStarted(context);

        String page = httpGet("http://127.0.0.1:" + port + "/");
        assertTrue("Web UI 应当是一份 HTML，实际开头是: " + preview(page),
                page.contains("<html") || page.contains("<!DOCTYPE"));

        String version = httpGet("http://127.0.0.1:" + port + "/api/version");
        assertTrue("/api/version 应当报出自己的名字，实际: " + preview(version),
                version.contains("subconv"));
    }

    @Test
    public void reportsVersionFromNativeLibrary() {
        assertNotNull(NativeServer.nativeVersion());
        assertTrue(NativeServer.nativeVersion().length() > 0);
    }

    private static String httpGet(String url) throws Exception {
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        try {
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(15000);
            assertEquals("GET " + url + " 应当返回 200", 200, connection.getResponseCode());
            return readAll(connection.getInputStream());
        } finally {
            connection.disconnect();
        }
    }

    private static String readAll(InputStream stream) throws Exception {
        StringBuilder builder = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                builder.append(line).append('\n');
            }
        }
        return builder.toString();
    }

    private static String preview(String text) {
        return text.length() <= 120 ? text : text.substring(0, 120) + "…";
    }
}
