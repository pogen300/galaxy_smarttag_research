package com.samsung.android.fmm;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import com.samsung.android.fmm.maze.FmmFontJNI;

import java.io.ByteArrayInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;

import java.security.PrivateKey;
import java.security.Signature;

import java.nio.charset.StandardCharsets;

public class MainActivity extends AppCompatActivity {
    private Context appContext;
    public String alias = "FMEKeyStore";
    public KeyStore mKeyStore;
    public String nonce = "5fc82673b7fc49d4bc06d03b2b8381b0";
    public String key, trustStorePath, rawkey, newAlias;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        appContext = getApplicationContext();
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Log.d("fmm main ","oncreate");
        // FmmFontJNI fmmFontJNI = new FmmFontJNI();
        key = "4I9DIqm5oKsUTam8"; // fmmFontJNI.getFMMFont1();
        Log.d("getfont key: ",key + "hex: "+stringToHex(key)); // 4I9DIqm5oKsUTam8

        rawkey = "JWAiVNBiMqlbHnvnMK9tahex"; // fmmFontJNI.getFMMFont3();
        Log.d("getfont rawkey: ",rawkey + "hex: "+stringToHex(rawkey)); // JWAiVNBiMqlbHnvnMK9tahex
        newAlias =  "dcbvkseluvkuwweqe";// fmmFontJNI.getFMMFont4();
        Log.d("getfont newAlias: ",newAlias); // dcbvkseluvkuwweqe


        trustStorePath = "1000_USRCERT_FMEKeyStore";//fmmFontJNI.getFMMFont2(appContext);
        Log.d("getfont trustStorePath: ",trustStorePath);

        mKeyStore = loadKeyStore();
        Log.d("fmedebug","loadKeyStore done");

        String x = getMazeAuthInfo(nonce);//getSAKAuthInfo(nonce);
        Log.d("fmedebug","getMazeAuthInfo done");

        if (x!= null) {
            Log.d("base64cert", x);
        }
    }
    static String stringToHex(String string) {
        StringBuilder buf = new StringBuilder(200);
        for (char ch: string.toCharArray()) {
            if (buf.length() > 0)
                buf.append(' ');
            buf.append(String.format("%04x", (int) ch));
        }
        return buf.toString();
    }
    private String getCert(Certificate[] certificateArr) {
        try {
            StringBuilder sb = new StringBuilder();
            if (certificateArr != null) {
                if (certificateArr.length >= 2) {
                    byte[] bArr = new byte[certificateArr[0].getEncoded().length + certificateArr[1].getEncoded().length];
                    System.arraycopy(certificateArr[1].getEncoded(), 0, bArr, 0, certificateArr[1].getEncoded().length);
                    System.arraycopy(certificateArr[0].getEncoded(), 0, bArr, certificateArr[1].getEncoded().length, certificateArr[0].getEncoded().length);
                    return Base64.encodeToString(bArr, 2);
                }
                Log.d("getCert","length < 2");
                return null;
            }
        } catch (Exception e) {
            Log.d("getCert",e.getMessage());
            return null;
        }
        Log.d("getCert","length 0");
        return null;
    }


    private String getMazeAuthInfo(String str) {
        try {
            String cert = getCert(mKeyStore.getCertificateChain(alias));
            if (TextUtils.isEmpty(cert)) {
                Log.d("getMazeAuthInfo cert: ","null");
                return null;
            }
            String sign = Base64.encodeToString(sign(str), 2);
            Log.d("getMazeAuthInfo cert: ",cert);
            return cert;
        } catch (Exception e) {
            Log.d("getMazeAuthInfo ",e.getMessage());
            return null;
        }
    }
    public byte[] sign(String str) {
        try {
            Key privateKey = getPrivateKey();
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign((PrivateKey) privateKey);
            signature.update(str.getBytes(StandardCharsets.UTF_8));
            return signature.sign();
        } catch (Exception e) {
            return null;
        }
    }

    Key getPrivateKey() {
        try {
            return this.mKeyStore.getKey(alias, rawkey.toCharArray());
        } catch (Exception e) {
            return null;
        }
    }


    KeyStore loadKeyStore() {
        KeyStore keyStore;
        try {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(Base64.decode(trustStorePath, 2));
            alias = newAlias;
            keyStore = KeyStore.getInstance("BKS");
            keyStore.load(byteArrayInputStream, key.toCharArray());
            Log.d("loadKeyStore done : ", "");
            try {
                byteArrayInputStream.close();
            } catch (Exception e3) {
                Log.d("loadKeyStore error : ", e3.getMessage());
                return keyStore;
            }
        } catch (Exception e4) {
            Log.d("keystore is null ", e4.getMessage());
            keyStore = null;
        }
        return keyStore;
    }


}