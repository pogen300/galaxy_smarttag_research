package com.samsung.android.fmm.maze;

import android.util.Log;

public class JniLoader {

    public static final int ERROR_CODE_OK                     = 0;
    public static final int ERROR_CODE_NOT_INITINED           = -1;
    public static final int ERROR_CODE_WRONG_TYPE             = -2;
    public static final int ERROR_CODE_WRONG_PARAMETER        = -3;
    public static final int ERROR_CODE_CRYPTED_FAILED         = -4;
    public static final int ERROR_CODE_NOT_ENOUGH_MEMORY      = -5;
    public static final int ERROR_CODE_EXCEED_MAX_LENGTH      = -6;
    public static final int ERROR_CODE_ALREADY_STARTED        = -7;
    public static final int ERROR_CODE_ALREADY_STOPED         = -8;
    public static final int ERROR_CODE_FAILED_TO_START        = -9;

    public JniLoader() {

    }

    public static boolean LoadLib() {
        try {
            System.loadLibrary("fmm_ct");
            Log.d("fmm_ct loaded","");
            return true;
        } catch (Exception ex) {
            Log.d("fmm_ct failed","");
            System.err.println("WARNING: Could not load library");
            return false;
        }
    }

    public native int GetProtoVersion();
    public native int GetLibVersion();


    public static native String getFont1();
    public static native String getFont2(Object obj);
    public static native String getFont3();
    public static native String getFont4();


}
