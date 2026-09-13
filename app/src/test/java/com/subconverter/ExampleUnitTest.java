package com.subconverter;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * 主机侧的纯 JVM 单测。
 *
 * <p>这里**测不了**转换逻辑：那份逻辑全在 C++ 里（libsubconv.so），而 .so 是按 Android ABI
 * 编的，JVM 加载不了。真正验证「服务能起来、端口是随机的、页面拿得到」的是
 * androidTest 里的 {@code NativeServerTest}（要跑在设备/模拟器上）。
 *
 * <p>所以这里只留能证明「测试基础设施是通的」的最小用例。
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class ExampleUnitTest {
    @Test
    public void addition_isCorrect() {
        assertEquals(4, 2 + 2);
    }
}
