package com.subconverter;

import android.util.Base64;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.GZIPInputStream;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * C++ 侧的抓取 / 证书探测后端。
 *
 * <p>NDK 既不带 libcurl 也不带 OpenSSL，交叉编译这两样东西不划算。所以把「发起请求」这件事
 * 交给 Java：TLS、重定向、代理、gzip、系统 CA 全部复用 Android 自己的网络栈。调用方是
 * {@code src/fetch/android_http.cpp}，那边的注释解释了为什么需要这座桥。
 *
 * <p>这个类只被 native 代码调用（Java 侧没有任何调用点），所以**必须**在
 * {@code src/main/keepRules/rules.keep} 里 keep 住，否则 R8 会把整类当死代码删掉，
 * 而 JNI 是按名字找方法的，删了就只剩 UnsatisfiedLinkError。
 */
public final class NetBridge {

    /** 与 C++ 侧 http.cpp 的 64MB 上限保持一致，防御异常响应把内存吃光。 */
    private static final int MAX_BODY_BYTES = 64 * 1024 * 1024;

    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    private NetBridge() {
    }

    /**
     * 单次 GET。对应 C++ 侧 {@code fetch::http_get} 的 Android 后端。
     *
     * <p>只有「网络层就失败了」才抛异常；非 2xx 会正常返回（把状态码写进 JSON），
     * 由 C++ 侧决定怎么报错 —— 这样两条后端（libcurl / Java）的报错文案一致。
     *
     * @return JSON：{@code {status, bodyBase64, effectiveUrl, contentType, headers}}
     */
    public static String get(String url, String userAgent, long timeoutSeconds,
                            long connectTimeoutSeconds, boolean followRedirects,
                            boolean insecure, String proxy, String[] headerNames,
                            String[] headerValues) throws Exception {
        URL target = new URL(url);
        Proxy javaProxy = parseProxy(proxy);
        URLConnection connection =
                (javaProxy == null) ? target.openConnection() : target.openConnection(javaProxy);

        HttpURLConnection http = (HttpURLConnection) connection;
        try {
            http.setRequestMethod("GET");
            http.setInstanceFollowRedirects(followRedirects);
            http.setConnectTimeout(clampTimeoutMs(connectTimeoutSeconds));
            http.setReadTimeout(clampTimeoutMs(timeoutSeconds));
            if (userAgent != null && !userAgent.isEmpty()) {
                http.setRequestProperty("User-Agent", userAgent);
            }
            // 刻意不自己设 Accept-Encoding：让 HttpURLConnection 自己去谈 gzip，
            // 它就会顺手把响应解压掉。若用户从 UI/CLI 传了这个头，我们也忽略它，
            // 免得出现「服务端返回 br，本地解不开」这种没人能诊断的失败。
            if (headerNames != null && headerValues != null) {
                int count = Math.min(headerNames.length, headerValues.length);
                for (int i = 0; i < count; i++) {
                    String name = headerNames[i];
                    String value = headerValues[i];
                    if (name == null || value == null || name.isEmpty()) {
                        continue;
                    }
                    if ("accept-encoding".equalsIgnoreCase(name)) {
                        continue;
                    }
                    http.setRequestProperty(name, value);
                }
            }
            if (insecure && http instanceof HttpsURLConnection) {
                HttpsURLConnection https = (HttpsURLConnection) http;
                https.setSSLSocketFactory(trustAllContext().getSocketFactory());
                https.setHostnameVerifier(ALLOW_ALL_HOSTNAMES);
            }

            int status = http.getResponseCode();
            byte[] body = readBody(http, status);

            JSONObject result = new JSONObject();
            result.put("status", status);
            // 正文走 base64：订阅文本里有中文/emoji，用 jstring 传会在 modified UTF-8 上出问题
            result.put("bodyBase64", Base64.encodeToString(body, Base64.NO_WRAP));
            result.put("effectiveUrl", String.valueOf(http.getURL()));
            String contentType = http.getContentType();
            result.put("contentType", contentType == null ? "" : contentType);

            JSONObject headers = new JSONObject();
            for (Map.Entry<String, List<String>> entry : http.getHeaderFields().entrySet()) {
                String name = entry.getKey();
                if (name == null) {
                    continue;  // 第一项是状态行，key 为 null
                }
                List<String> values = entry.getValue();
                if (values == null || values.isEmpty() || values.get(0) == null) {
                    continue;
                }
                headers.put(name.toLowerCase(Locale.ROOT), values.get(0));
            }
            result.put("headers", headers);
            return result.toString();
        } finally {
            http.disconnect();
        }
    }

    /**
     * 对端叶子证书的 SHA-256 指纹（冒号分隔的大写十六进制）。
     *
     * <p>与上游 OpenSSL 实现同语义：**不校验**证书链与主机名（目的就是「证书不可信 /
     * 与 SNI 对不上」的节点也能拿到指纹），指纹算在叶子证书的 DER 上。
     *
     * @param sni 空则用 host
     */
    public static String peerCertSha256(String host, int port, String sni, int timeoutSeconds)
            throws Exception {
        if (host == null || host.isEmpty() || port <= 0) {
            throw new IllegalArgumentException("探测证书需要合法的 host:port");
        }
        int timeoutMs = clampTimeoutMs(timeoutSeconds);

        SSLSocketFactory factory = trustAllContext().getSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket();
        try {
            socket.setSoTimeout(timeoutMs);

            String serverName = (sni == null || sni.isEmpty()) ? host : sni;
            try {
                SSLParameters parameters = socket.getSSLParameters();
                parameters.setServerNames(Collections.singletonList(new SNIHostName(serverName)));
                socket.setSSLParameters(parameters);
            } catch (IllegalArgumentException ignored) {
                // 不是合法 SNI 主机名（比如 IP 字面量）就跳过：设不上不影响握手
            }

            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.startHandshake();

            Certificate[] chain = socket.getSession().getPeerCertificates();
            if (chain == null || chain.length == 0) {
                throw new SSLException("对端没有提供证书");
            }
            return sha256Fingerprint(chain[0].getEncoded());
        } finally {
            try {
                socket.close();
            } catch (IOException ignored) {
                // 关闭失败无关紧要
            }
        }
    }

    // -----------------------------------------------------------------------
    // 内部实现
    // -----------------------------------------------------------------------

    private static byte[] readBody(HttpURLConnection http, int status) throws IOException {
        // 4xx/5xx 的错误页在 errorStream 里，getInputStream() 会直接抛 IOException
        InputStream stream = (status >= 400) ? http.getErrorStream() : http.getInputStream();
        if (stream == null) {
            return new byte[0];
        }

        // 只有当 Content-Encoding 还在（说明是我们自己或用户显式要的 gzip、
        // HttpURLConnection 没有代劳）时才手动解压。
        String encoding = http.getContentEncoding();
        if (encoding != null && encoding.toLowerCase(Locale.ROOT).contains("gzip")) {
            stream = new GZIPInputStream(stream);
        }

        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[16 * 1024];
            long total = 0;
            int read;
            while ((read = stream.read(buffer)) != -1) {
                total += read;
                if (total > MAX_BODY_BYTES) {
                    throw new IOException("响应体超过 " + MAX_BODY_BYTES + " 字节上限");
                }
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        } finally {
            try {
                stream.close();
            } catch (IOException ignored) {
                // 关闭失败无关紧要
            }
        }
    }

    /**
     * 解析代理 URL：{@code http://} / {@code https://} / {@code socks5://} /
     * {@code socks5h://} / {@code socks4://}，也可以只写 {@code host:port}（按 http 处理）。
     * 返回 null 表示不用代理。
     */
    private static Proxy parseProxy(String proxy) {
        if (proxy == null) {
            return null;
        }
        String text = proxy.trim();
        if (text.isEmpty()) {
            return null;
        }

        String scheme = "http";
        String rest = text;
        int marker = text.indexOf("://");
        if (marker > 0) {
            scheme = text.substring(0, marker).toLowerCase(Locale.ROOT);
            rest = text.substring(marker + 3);
        }
        int at = rest.lastIndexOf('@');
        if (at >= 0) {
            rest = rest.substring(at + 1);  // 丢掉 user:pass@（暂不支持带认证的代理）
        }
        int slash = rest.indexOf('/');
        if (slash >= 0) {
            rest = rest.substring(0, slash);
        }

        String host;
        int port;
        if (rest.startsWith("[")) {  // IPv6 字面量 [::1]:1080
            int close = rest.indexOf(']');
            if (close < 0) {
                return null;
            }
            host = rest.substring(1, close);
            int colon = rest.indexOf(':', close);
            port = (colon > 0) ? parsePort(rest.substring(colon + 1)) : -1;
        } else {
            int colon = rest.lastIndexOf(':');
            if (colon < 0) {
                host = rest;
                port = -1;
            } else {
                host = rest.substring(0, colon);
                port = parsePort(rest.substring(colon + 1));
            }
        }
        if (host.isEmpty() || port <= 0) {
            return null;
        }

        if (scheme.startsWith("socks")) {
            // createUnresolved 是关键：这样 Java 会把域名原样交给代理解析（socks5h 的语义），
            // 而不是本地先做一次 DNS —— 订阅场景下本地 DNS 往往正是被污染的那个。
            return new Proxy(Proxy.Type.SOCKS, InetSocketAddress.createUnresolved(host, port));
        }
        return new Proxy(Proxy.Type.HTTP, new InetSocketAddress(host, port));
    }

    private static int parsePort(String text) {
        try {
            int port = Integer.parseInt(text.trim());
            return (port > 0 && port <= 65535) ? port : -1;
        } catch (NumberFormatException ignored) {
            return -1;
        }
    }

    private static int clampTimeoutMs(long seconds) {
        long millis = Math.max(1L, seconds) * 1000L;
        return (int) Math.min(millis, Integer.MAX_VALUE);
    }

    private static String sha256Fingerprint(byte[] der) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(der);
        StringBuilder builder = new StringBuilder(digest.length * 3);
        for (byte value : digest) {
            if (builder.length() > 0) {
                builder.append(':');
            }
            builder.append(HEX[(value >> 4) & 0x0F]);
            builder.append(HEX[value & 0x0F]);
        }
        return builder.toString();
    }

    private static final X509TrustManager TRUST_ALL_MANAGER = new X509TrustManager() {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    };

    private static final HostnameVerifier ALLOW_ALL_HOSTNAMES = new HostnameVerifier() {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    };

    private static volatile SSLContext trustAllContextCache;

    private static SSLContext trustAllContext() throws Exception {
        SSLContext cached = trustAllContextCache;
        if (cached != null) {
            return cached;
        }
        synchronized (NetBridge.class) {
            if (trustAllContextCache == null) {
                SSLContext context = SSLContext.getInstance("TLS");
                context.init(null, new TrustManager[] {TRUST_ALL_MANAGER}, new SecureRandom());
                trustAllContextCache = context;
            }
            return trustAllContextCache;
        }
    }
}
