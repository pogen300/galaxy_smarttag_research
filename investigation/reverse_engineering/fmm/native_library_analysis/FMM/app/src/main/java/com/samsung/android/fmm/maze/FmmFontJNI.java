package com.samsung.android.fmm.maze;
/*
public class FmmFontJNI {
    private static JniLoader jniLoader;
    private static boolean libLoaded = false;

    public static void init() {
        if (!libLoaded) {
            libLoaded = JniLoader.LoadLib();
        }
        if (libLoaded) {
            jniLoader = new JniLoader();
        }
    }

    public static int GetProtoVersion() {
        return jniLoader.GetProtoVersion();
    }

    public static int GetLibVersion() {
        return jniLoader.GetLibVersion();
    }

    public static String getFMMFont1() {
        return JniLoader.getFont1();
    }

    public static String getFMMFont2(Object obj) {
        return JniLoader.getFont2(obj);
    }

    public static String getFMMFont3() {
        return JniLoader.getFont3();
    }

    public static String getFMMFont4() {
        return JniLoader.getFont4();
    }
}
*/

public class FmmFontJNI {
    private native String getFont1();

    private native String getFont2(Object obj);

    private native String getFont3();

    private native String getFont4();

    static {
        System.loadLibrary("fmm_ct");
    }

    public String getFMMFont1() {
        return getFont1();
    }

    public String getFMMFont2(Object obj) {
        return getFont2(obj);
    }

    public String getFMMFont3() {
        return getFont3();
    }

    public String getFMMFont4() {
        return getFont4();
    }
}