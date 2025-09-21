package com.tesla.easyso1;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import androidx.appcompat.app.AppCompatActivity;

import com.tesla.easyso1.databinding.ActivityMainBinding;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Locale;

import javax.crypto.Cipher;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";
    // RSA 公钥加密 私钥解密
    public static final String pk = "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA67s2IdcCvkfndK4BoR5JXuOkfzYM7z9y81CX++F2zFYW70OTbcBxweuaR3kRKW7bAGFLJ+D70Ih2NuZP1ZYoSrcft/bs6kZQEzm7PowrO3AGe7fQbRy2ayf2AQGhEe6xMTheH0TkaE0d+zW3ZneJ9O8KNkWACA4IUxwke1I/gc8JwjQlIL2+cfsgjUpVflJEzUFuADdJh57QgTYc7yt8bISmo4L9PmivOrQsIpD3DPYGqi9RCmGoQ8npEfXwy72FKy2aDBIkoNsgzwsBt1CcUY5dSEuodkiWXtaYUMcypaTf9pgCp35AWwQJcSeP7rGENbYhdesFs3maK8SYsYOUfZ0WgaukdS9gmXJ8gPwIMW4QDoDa+r5KK0MnvZWvg3pcbX/H2IwghnMWwsRRDLIJiP5sKiE7NW8Ld4z1sYOmLj42/WLoezKGK3Ul7z0pBvWH8DgklMzqsEc5E7Zf4rSWcNlYhywMhGwd2PWgYWta2nM+cjbJ6yLdcn9Tk1cnWhFFAgMBAAE=";

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

        String cnt = "H4sIAAAAAAAAANVYWa+jSpL+L+fhvFDnQCZ7SUctsMHGgME2YKA1KrGD2XfwrfvfG9et6WnNqNXP443IyMggI4iML8LYzz/egix8+/4GAImxJI3Dt29vQfeLxQYY5cPQ+wh8jPggGEB8sHQYfWCAo" +
                "NmAwUI/ZjZpb2jevoPXquHtO/z21g+/Vrd03DKPR1vMm0wUbnOAhhRFk4BlMQz79tb0b9//eNv4bxCDBMYCBuIkS7IvlS/mz59OfeAvZ6EhWzQbnJGY2Hp5XliBvUiDxiaZgvbsPRJRRIhzKSBBg1mHQ2pNxL7KxNxC81N4pEO8paNYTyOGxoZ7e4W8wdDdPHhNajshqCsPYML" +
                "KELi/kz3xQmXoc5kaFznOsr2cnsdjofjnB1BsPS/D0ro77F4o0sfBswsE9zkJG7PdFSldU1olfzBiXPYnvlXIXCHueEA2EbIX4czTZY62/mUnjSkyx6WS3nEY3ApOiOv9sakwDq/lskjI26Vw4J17Pg2nyUzn2C0sdFZB9YqbcDVUK9fOZRA9NDBy7YXQzuoTa12ZBoyTSSogz" +
                "BJv9eNEuI2u1/Oey/eXlKcnavcUKMty7gWzh8+bAFGuEUe3WPziOkPcCSwZ3CzNTLmb3K1tlNBM5ZH+1OS73UlRz4/Sbv2ulx4Jp10fz4WMUIaqg9VubtgKcVeL2POigMEge+XQ7TWrExhCpAWCAPvYMez6iQcnsjvoj+h8XmsK9RTiWEDGy2lCU9tDpyxP0/V8RggqXXNNpQ4" +
                "PLn0Jz7qZybOgOR2C3of+IuB7WHZlckV3h4xGT6pyz7Ow9Sc6b3DLevAceqz4m1Bc3M4dbT/RkLOkSqWcyTQbQ8UUliU9rTnmx6wnnKw1o4/2HDYmg2jF8rwqq7VIpZqGK5K2rTY1KjGiBrzvSMHGLAAOaIsWY88HN72K94tblMV6wttaHxpXWE4EDvAS4+I+cwo8t5JJ4NJD7" +
                "RK79qgOg2ZRxxh0GKPJ6hh2Y3As9wonTijdKQZ01P5i3yJTJzRCLHjfskDmgT7J+ftM29Uyc7vbaNkt1YSpaUubZ6MblhLmEQf9jm/V87rYJKcrVzZzr2HT16dYvoTcvHfVtkCQtkZK/vjAKHW0p0mUHQ+GztTWOwd/7M/3kq4O63pqqCuzGLO2PsehVqpCPbu6LDQYQWlPKWr" +
                "SA4hRm/LwnlMMXCnE8Xx27uR6e+YOMfDYJbynyRgyPN11hnJd6lPULoq06qbo7nRPrpnYKKaiiDV6JEqRP11ELF/L8TjdWEGQxO15sK5S0fqzj5/5nGdJAhYsxo+WHEF6UHc5Yl9noz3eDhVjN2FxnjkxotSGD20eh72qW/qMFQfRZEAYeVClGmI4p9tRnw42cTEUsdJ4JvdoQ" +
                "q09rCi7mCyuq8V1+eO65/bqPBdi0XX7UhOnRFl7STwqp4MEIBtj8oyVJ6DDKy8IVsEip+ow8E+bRxoeCbRhJ/oGIwyeukhDnGk0ZT8dip3uGukg4nTTKUYpSpvIYaF2R4g33eFq3FwB9S4n7hRL4xzE+YCE6oFSqwwKEzehAewOdhEmjYPuxmZXgmsiNNb1OI4corJOcPBCNcw" +
                "tKlyz2zEoVfLpmkvpaw36WOo9s/g1AOgenBKVT0roX0SWZsFSlYjDhegpK3V2GW/8hQ9SsA+44+PeK/WCkCt+yhiKd3r74Rgze1gToAWOt5yiwTMcTMZ26x6XSFna00O21LE+9+uhOaaUBAVu3MI8y7JrHAuVWdPKTK/MMdDkHYFwh2A2LhP73N/KTMMaMS8IReF3WFsxC11GX" +
                "HbxNCuK5DzTVxe4emxr9gQmcV+1D4GLzUUOsMuwByjKWvd8ECbyfo/NPPnaEKPPkg0z3v789lYO4QtXgnEbp8PQ9N9RNCXTeoOlKvkIu6D6DH2vyoOw+gwqNAhSEtX1G4oDBmc96Hk09AgSeCwdBBgWRAzpxxQFQvQ3SgHAYjQEkQ8jJvJwEkaQgIBmQoymQjokIhbGBIw/06E" +
                "s/lZ7WfgVAJyOCJxlWIwJcUAxGIUTHs2yWxwGMYzex3CTWuO+CNHe53eON4Q0bzxT2bUE936/3DivhAonsz1+JDt42mJ8t8AQDLlSPxSTtztrajCjJPu4viWgy43qVJsSAPC5Y/ktsSogusrhfjxNzG7NFzNkhlt4WeXl8WhiVf1676I46rqo+0pHb44yL+x//DaX2tyyoQtgi" +
                "A22cZZ6D6TwC4eApQDJvHvhLRo2BkFBhmTwF2Mb/bOWeO+zIfoC703T/yiaH4UX/8+g+deB99cg7r2vDffFOVlwZT2bC5J3g3Lu+3CL+kw6nNvgAqvhctjp+T5XrrNbn8Zdf01Bvl4Zt6jRAgkVOm6W4ypXLYvHvorCWuZkF/AjG7cP+qxIV/052YmzsEmlBXF2FseYQa8krKJ" +
                "BXqccRw3+St+p0czmAZl1pjDxPb7I8iWfklRAIuLmDjYC9AAwltkGD6HaNx5HiuPU38/OA5mlcjnI11MqMJahSjvDmalO9FC79CTApSRHh2rZpPvgwjQeYj0EbeJavGZZ3zc2+zRyevIPrOp21TMVbepkJuDh0hNSsNRgUqoMYlfEVxArsVGv9dPPj0/BWuZkDVEFQ7EZ6hLHL" +
                "lyErNYBCCakXf2EC0fsDhqkqXDl5h/csQ3d7ZjWjTGfRdZNK+AI/XYSkFugN6r0LMaFqq867t2bShlhQgIz4YYKBnDk8WSIljN4ZnBknFi4RxWpy66U3+jCqHPYLP2hdlzaVATMwcbSZ+JKGpZ7owIFv3AM6WF8nltBJ/qAT8FBnijfHZhi6gwuuqPXy3BooDpnY+4F7hH3ilI" +
                "nLgi9T1IjTc73FiG11byMxD5Sg7w14p3uu5cbyWpcFkaP9ommZzu5bemVNg5mVKROLgprZxqSr4mOLq2CJdu4ZhDGwmZSgTVMf8TxXdwMx7M2352wVWJFaYaxvZuOfJAE9FwCaDOUcr+TA00WCFcdT2xULkwGIyJ0HJi1RmaKkdXnNMI5FeXt9fOMxgnycJ0YstNxy6XnqhdnY" +
                "5G2gwlIqrpcTwEmcroWXkOqlQ0b8WAS85XhACI3rpHOjMXtfNFGMkzZ06Lz+3BxeZ+sBnNAuCYpeJSL3Htf+ElN+a2E1QiIieWG61dsr7eiru3pSWsnEE2T+ry47o25MX62sLkXTdR1Zc8HTsmucCiaygbHNGCSAtAbsjjtXC52nepFmqZEUcpbuWZfvTNoEejv8SjGmTJTmMz" +
                "knNngxbnzSbQxb/Wdv46ca9sOh6nMpNtPgzgpXtPhlh9Nu6S/peShynemapDzTFr0QBjgOB3HYz+396E5bGWIeSY5ckiShN8tuPe48UeOiDVCeazzpTY8s5CfrgtVO0WfSXv29Q3R6pJQmNZJvl4YkJVZ/Pb973+8/WvqD+pqiKoh2L5R93/T/zQNP8Ar///YBKsoGOoODQt0S" +
                "0to2Dc/xq74nQgxHJAkgW9lFynsCGxHCGBHELjAERy/FfhgT/HcVuyKn48m2fYyb+0OxmxdTroRFHwR/Ua+MXHoERjGRDhNYgSNexRkCSYgMAYGeEjGIYZRNI3hOMS2O3o+hH5A4UG4ZdyIjiF4dWfpZiX487++vRXNr+7phXpD/qvp+u88/PbCwV++eElkZbMxNq/8/Z9uCYP" +
                "+M2uyaq3Hz6Au0U0EvRwsL8Eqxrwrhg6ZT4ZjYxX7Wxd+/fhhSKpwMzhV//HjPSuj7Ov9F7TFVMDGcUx9xGQcfFA+iD82I+gPEL4YtEdhJPGehbG3qZD2IretLr3g6z1rNpCAnwD7hBj+yYL3cRMwr8o2X/df2PvQ/697dlGbvfZxFS7mxtyUbczxpdbclL5tzvjllG9/GRwUW" +
                "ZD/J5ODIv83Jn8mWfz/yuztOgevAqiPBjVbonD3V9SrdRj9zKrhJ/Ztm9nX5W2Lby+JhMrziyj86dd1EXnVz6Ebo1dkDf3rn4CtOwfbz/aB2xVCuJGv9wf2+/Xxmtzkh99NPcHgGM6QcGv+m/y1jc29n39VEp9+V8991L2OxFK8SrQX8StW3/78B6ENMoZ+EAAA";
        String sig = "XalwhQZHtDQy57XQm" +
                "6sOmJEQv9Lk5B0Bl000eIVYPJ3ifA2TVhTqIjvBm9ecZN/ALleIU2Iw0H1/rz1zY/PpwKrejff1QcSzWDCH7rE0AJndxYOnhb+MrgBD+1NaokdPWFo4xkMkUqDLbl4PInsW/3cprh5k67e3V1g0+dLo5UCZVrpbFMU328EMdNHPgpoG7NFnkZ1EvwFoNmLqP9ww9Wcw2M1m4qe" +
                "/BRRluY3M52pLVbyVePSGTzmG5G554ukcrFwDJpBZaFbmqDahZRO4rrTXabzwl1UkJ/Nn2j5iGWfMDY8rNJYfIww2Gi0vMd5o41g3+u+lPFCb7iZcx6gDBXSCNi/jjVu2xndBvQ+pDyAMcGMCDF1SqH/fMXf2/v1A0ubgkGRO1srBu5GzNkqjSaG4Rux/kfEnlf2a1FT7vhjfa" +
                "E1pS2wdgZ6oq4cNtn86M8EmWChMF5mNm12wHyO77ZMnbuA2y2cjBq+x8etMmWUGG7EB+5ZsRlPdw7GcM9am";
//         String cnt = "uvUUt/gj0NMD1382pMTOM6wQHC//wXEgLpieA+IO7hs3I+jthrUdeyGH3oc99NWSGi4mmxQfSPHnxTRxaedeNNCuK8Yffj3fVOKEeCVOxKVdc99fjgBuhWwvGP8ZNktHT6fPO9MT/1HJmIH5vaF0mBe9Jm/oyzY6tuYHy/o7O/LUcvmpLAoWAGSAQYjLAd00O/XG+8hlfNWko0IXSJbVc09uL59VPeip5jcTX4GJp3HXFXQRBkj6Z3wPQkFDdcLOgI7wQtR9b3TdyOf1vykH3ZEd+LDhhpmBTnh8q56wWbyjH73GighUDe3Fy9rRQNc54HFfmxqyOW/1oww/6LnofMLRL3AAzaOJC+5kbGAkSRqSFRkEijEHO5ujC4B1CiWz1ZTC6F6trAUoHoWTAicXX7z0dAz2rOSVkVAjbRchO2XmDZp6S8AGcWU9Fjj2s3m1blt4nyCkrm6+/2L7+i2QhOnw0fSK5C3yJVUdDkVbwO2RC96RCVfxVIrULMuSDpGW";
//         String sig = "AnEubghSILxL1dcD0Gu9FGw1aUK2VGqn5DtVLycDQpVi8By13GKIbcTh1YB1ji5aFnZ1j7SAyAFOlS/bcZk1+qrxzEVmzz/0n+R06NcR3kEyO6BZ9yO9Z+goKR3vq9haGvHndgZAOJEfz4HBGdRe1S+aeE+2gBGoEb+ZcQjrY9oEhLJUnlxttEm5r2Py3hI2zspjObwSLhWcPArKTxJ+EGTSPbMTo92QTj8od7FnhCm2TmQuUpkgpbOL3dAudENt4rE7uS1MdJiRiOkz8saNzpWPVFhSTlILT/tnReBj8IJ1nW1ZjwQRGwi4HWk7TxjeZffuXWaC6DdKmSwXwrtYaIqe2rXvtRZlDce3nFNuANOIntJ53v2EE9/l3mF0FEtyOeaC1p2PVi0yu/vTU5xc1A/nqRH4tfK79Zm7jW685KcrOa3KougOmrcBss/2Q0Sm4e8oCQQZ8VYTZtTroFFtW4oB1BFIRzgsCZLB/0ZPhgjQ9RU9ARnmNDAng4+A4wQc";

        boolean ret = false;
        try {
            ret = this.verify(cnt, sig);  // 返回结果跟项目执行一致
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        Log.d(TAG, "onCreate: " + ret);
        System.out.println(TAG + " onCreate: " + ret);

        /*
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
         */

//         Intent intent = new Intent(this, MainActivity2.class);
//         Intent intent = new Intent(this, MainActivity3.class);
//         startActivity(intent);

        // 跳转华为快应用 可以实现
        Intent intent = new Intent(Intent.ACTION_VIEW);
        //Uri uri = Uri.parse("hap://app/com.shayu.bizhi/hssdk/blank?qid=199&lid=2225&aid=2225&did=2225&source=ks&h=1&");  // 直接打开快应用
        Uri uri = Uri.parse("https://www.baidu.com");  // 一般会用浏览器打开
        intent.setData(uri);
        //intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

        // debug
        // 这个加了跳转不成功 崩溃 华为快应用不需要这个action
        // intent.setAction("com.huawei.phoneservice.intent.action.QRCODE_FROM_3RD");
        // 这两个错误加也可以跳转快应用
        intent.addCategory("android.intent.category.DEFAULT");
        intent.addCategory("android.intent.category.BROWSABLE");
        // 这个设置错了也不能跳转快应用
        //intent.setComponent(new ComponentName("com.huawei.phoneservice", "com.huawei.myhuawei.ui.HwDeeplinkActivity"));  // 跳我的华为
        //intent.setComponent(new ComponentName("com.huawei.phoneservice", "com.huawei.myhw.ui.HwHomeActivity"));  // 崩溃
        //intent.setComponent(new ComponentName("com.huawei.fastapp", "com.huawei.fastapp.app.protocol.WebInterruptedActivity"));  // 崩溃

        this.startActivity(intent);

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

    public boolean verify(String cnt, String sig) throws UnsupportedEncodingException {
        // 对cnt进行url编码 再sha256加密
        String cnt_sha256 = sha256Encrypt(URLEncoder.encode(cnt, "UTF-8"));
        // 正确结果 726e693d6d2963e02ed16fb2a1fcb973268d678134aaa42556011857f077de4e
        System.out.println(cnt_sha256);

        try {
            if (check(cnt_sha256, sig, false)) {
                return true;
            }
            return check(cnt_sha256, sig, true);  // 走的这个分支返回true
        } catch (Exception e2) {
            return false;
        }

//        VerificationResult ret = checkv2(cnt_sha256, sig, false);
//        Log.d(TAG, "verify: " + ret.toString());
//        return false;
    }

    public static String sha256Encrypt(String cntUrlEn) {
        if (TextUtils.isEmpty(cntUrlEn)) {
            return "";
        }
        try {
            return sha256Result(MessageDigest.getInstance("SHA-256").digest((cntUrlEn.getBytes("UTF-8"))));
        } catch (UnsupportedEncodingException unused) {
            return "";
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static String sha256Result(byte[] bArr) {
        if (bArr == null || bArr.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (byte b2 : bArr) {
            String hexString = Integer.toHexString(b2 & 255);
            if (hexString.length() == 1) {
                sb.append('0');
            }
            sb.append(hexString);
        }
        return sb.toString();
    }

    public boolean check(String cnt_sha256, String sig, boolean z) {
        try {
            Signature signature = Signature.getInstance(z ? "SHA256withRSA/PSS" : "SHA256withRSA");
            signature.initVerify(KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.decode(pk, 2))));
            signature.update(getBs(cnt_sha256));

            // 计算RSA加密cnt 使用公钥加密数据
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decode(pk, Base64.DEFAULT));
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            // 初始化 Cipher，选择使用 RSA/ECB/PKCS1Padding 加密
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            // 对输入的cnt数据进行加密
            // byte[] encryptedData = cipher.doFinal(getBs(cnt_sha256));
            byte[] encryptedData = cipher.doFinal(cnt_sha256.getBytes("UTF-8"));

            // 返回 Base64 编码的加密结果
            String rsa_cnt = Base64.encodeToString(encryptedData, Base64.DEFAULT);
            Log.d(TAG, "check: " + rsa_cnt);
            System.out.println(TAG + " check: " + rsa_cnt);

            return signature.verify(Base64.decode(sig.getBytes("UTF-8"), 2));
        } catch (Exception e2) {
            return false;
        }
    }

    public byte[] getBs(String cnt_sha256) {
        StringBuilder sb;
        byte[] bArr = new byte[0];
        try {
            return getBsCustom(cnt_sha256);
        } catch (NumberFormatException e2) {
            return bArr;
        } catch (Throwable th) {
            return bArr;
        }
    }

    /**
     * 自定义算法
     *
     * @param cnt_sha256
     * @return
     * @throws UnsupportedEncodingException
     * @throws NumberFormatException
     */
    public byte[] getBsCustom(String cnt_sha256) throws UnsupportedEncodingException, NumberFormatException {
        String upperCase = cnt_sha256.toUpperCase(Locale.ENGLISH);  // 转大写
        int length = upperCase.length() / 2;
        byte[] bArr = new byte[length];
        byte[] bytes = upperCase.getBytes("UTF-8");
        for (int i2 = 0; i2 < length; i2++) {
            StringBuilder sb = new StringBuilder();
            sb.append("0x");
            int i3 = i2 * 2;
            sb.append(new String(new byte[]{bytes[i3]}, "UTF-8"));
            bArr[i2] = (byte) (((byte) (Byte.decode(sb.toString()).byteValue() << 4)) ^ Byte.decode("0x" + new String(new byte[]{bytes[i3 + 1]}, "UTF-8")).byteValue());
        }
        return bArr;
    }

    public VerificationResult checkv2(String cnt_sha256, String sig, boolean z) {
        try {
            Signature signature = Signature.getInstance(z ? "SHA256withRSA/PSS" : "SHA256withRSA");
            signature.initVerify(KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.decode(pk, 2))));
            signature.update(getBs(cnt_sha256));

            // 获取加密值
            boolean isValid = signature.verify(Base64.decode(sig.getBytes("UTF-8"), 2));
            if (!isValid) {
                // 校验失败，返回失败信息
                return new VerificationResult(false, "Signature verification failed.", sig);
            }

            return new VerificationResult(true, null, sig);
        } catch (Exception e) {
            return new VerificationResult(false, e.getMessage(), null);
        }

    }
}
