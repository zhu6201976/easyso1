package com.tesla.easyso1;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Bundle;
import android.telephony.TelephonyManager;
import android.util.Log;
import android.widget.TextView;

import com.tesla.easyso1.databinding.ActivityMainBinding;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";

    // Used to load the 'easyso1' library on application startup.
    static {
        System.loadLibrary("easyso1");
    }

    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // Example of a call to a native method
        TextView tv = binding.sampleText;
        tv.setText(stringFromJNI());

        // 静态注册
        String encrypt = method01("123456");
        Log.d(TAG, "onCreate: encrypt " + encrypt);
        String decrypt = method02(encrypt);
        Log.d(TAG, "onCreate: decrypt " + decrypt);
        // 动态注册
        String signRet = sign("123456");
        Log.d(TAG, "onCreate: signRet " + signRet); // 3b42f5199dbd80c2c59c3cc60f194e36e9cf0a3e97a602e70e3449cbaa8dd8a3f96c7d8eebda9a5e8bf4351c081b833f3029271ad36ae0b1605727e38cbc75943e4dccbd039c3784216847c7eea4a0a8fc9ab8c14e899881f5e5360257cb2bd8
        String decryptSignRet = method02(signRet);
        Log.d(TAG, "onCreate: decryptSignRet " + decryptSignRet);  // 123456google/blueline/blueline:9/PQ3A.190801.002/5670241:user/release-keys

        // debug
        TelephonyManager tm = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
        @SuppressLint("HardwareIds") String device_id = tm.getDeviceId();
        int phone_type = tm.getPhoneType();
        @SuppressLint("HardwareIds") String simserialnumber = tm.getSimSerialNumber();
        Log.d(TAG, "onCreate: device_id " + device_id + " phone_type " + phone_type + " simserialnumber " + simserialnumber);
    }

    /**
     * A native method that is implemented by the 'easyso1' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();

    /**
     * AES加密, CBC, PKCS5Padding
     */
    public static native String method01(String str);

    /**
     * AES解密, CBC, PKCS5Padding
     */
    public static native String method02(String str);

    /**
     * 动态注册 native 环境检测
     */
    public static native String sign(String str);
}