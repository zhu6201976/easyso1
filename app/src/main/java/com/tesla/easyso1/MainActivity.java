package com.tesla.easyso1;

import android.os.Bundle;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

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

import androidx.appcompat.app.AppCompatActivity;

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

        // String cnt = "H4sIAAAAAAAAANVYWa%2BjSpL%2BL%2BfhvFDnQCZ7SUctsMHGgME2YKA1KrGD2XfwrfvfG9et6WnNqNXP443IyMggI4iML8LYzz%2Fegix8%2B%2F4GAImxJI3Dt29vQfeLxQYY5cPQ%2Bwh8jPggGEB8sHQYfWCAoNmAwUI%2FZjZpb2jevoPXquHtO%2Fz21g%2B%2FVrd03DKPR1vMm0wUbnOAhhRFk4BlMQz79tb0b9%2F%2FeNv4bxCDBMYCBuIkS7IvlS%2Fmz59OfeAvZ6EhWzQbnJGY2Hp5XliBvUiDxiaZgvbsPRJRRIhzKSBBg1mHQ2pNxL7KxNxC81N4pEO8paNYTyOGxoZ7e4W8wdDdPHhNajshqCsPYMLKELi%2Fkz3xQmXoc5kaFznOsr2cnsdjofjnB1BsPS%2FD0ro77F4o0sfBswsE9zkJG7PdFSldU1olfzBiXPYnvlXIXCHueEA2EbIX4czTZY62%2FmUnjSkyx6WS3nEY3ApOiOv9sakwDq%2FlskjI26Vw4J17Pg2nyUzn2C0sdFZB9YqbcDVUK9fOZRA9NDBy7YXQzuoTa12ZBoyTSSogzBJv9eNEuI2u1%2FOey%2FeXlKcnavcUKMty7gWzh8%2BbAFGuEUe3WPziOkPcCSwZ3CzNTLmb3K1tlNBM5ZH%2B1OS73UlRz4%2FSbv2ulx4Jp10fz4WMUIaqg9VubtgKcVeL2POigMEge%2BXQ7TWrExhCpAWCAPvYMez6iQcnsjvoj%2Bh8XmsK9RTiWEDGy2lCU9tDpyxP0%2FV8RggqXXNNpQ4PLn0Jz7qZybOgOR2C3of%2BIuB7WHZlckV3h4xGT6pyz7Ow9Sc6b3DLevAceqz4m1Bc3M4dbT%2FRkLOkSqWcyTQbQ8UUliU9rTnmx6wnnKw1o4%2F2HDYmg2jF8rwqq7VIpZqGK5K2rTY1KjGiBrzvSMHGLAAOaIsWY88HN72K94tblMV6wttaHxpXWE4EDvAS4%2BI%2Bcwo8t5JJ4NJD7RK79qgOg2ZRxxh0GKPJ6hh2Y3As9wonTijdKQZ01P5i3yJTJzRCLHjfskDmgT7J%2BftM29Uyc7vbaNkt1YSpaUubZ6MblhLmEQf9jm%2FV87rYJKcrVzZzr2HT16dYvoTcvHfVtkCQtkZK%2FvjAKHW0p0mUHQ%2BGztTWOwd%2F7M%2F3kq4O63pqqCuzGLO2PsehVqpCPbu6LDQYQWlPKWrSA4hRm%2FLwnlMMXCnE8Xx27uR6e%2BYOMfDYJbynyRgyPN11hnJd6lPULoq06qbo7nRPrpnYKKaiiDV6JEqRP11ELF%2FL8TjdWEGQxO15sK5S0fqzj5%2F5nGdJAhYsxo%2BWHEF6UHc5Yl9noz3eDhVjN2FxnjkxotSGD20eh72qW%2FqMFQfRZEAYeVClGmI4p9tRnw42cTEUsdJ4JvdoQq09rCi7mCyuq8V1%2BeO65%2FbqPBdi0XX7UhOnRFl7STwqp4MEIBtj8oyVJ6DDKy8IVsEip%2Bow8E%2BbRxoeCbRhJ%2FoGIwyeukhDnGk0ZT8dip3uGukg4nTTKUYpSpvIYaF2R4g33eFq3FwB9S4n7hRL4xzE%2BYCE6oFSqwwKEzehAewOdhEmjYPuxmZXgmsiNNb1OI4corJOcPBCNcwtKlyz2zEoVfLpmkvpaw36WOo9s%2Fg1AOgenBKVT0roX0SWZsFSlYjDhegpK3V2GW%2F8hQ9SsA%2B44%2BPeK%2FWCkCt%2ByhiKd3r74Rgze1gToAWOt5yiwTMcTMZ26x6XSFna00O21LE%2B9%2BuhOaaUBAVu3MI8y7JrHAuVWdPKTK%2FMMdDkHYFwh2A2LhP73N%2FKTMMaMS8IReF3WFsxC11GXHbxNCuK5DzTVxe4emxr9gQmcV%2B1D4GLzUUOsMuwByjKWvd8ECbyfo%2FNPPnaEKPPkg0z3v789lYO4QtXgnEbp8PQ9N9RNCXTeoOlKvkIu6D6DH2vyoOw%2BgwqNAhSEtX1G4oDBmc96Hk09AgSeCwdBBgWRAzpxxQFQvQ3SgHAYjQEkQ8jJvJwEkaQgIBmQoymQjokIhbGBIw%2F06Es%2FlZ7WfgVAJyOCJxlWIwJcUAxGIUTHs2yWxwGMYzex3CTWuO%2BCNHe53eON4Q0bzxT2bUE936%2F3DivhAonsz1%2BJDt42mJ8t8AQDLlSPxSTtztrajCjJPu4viWgy43qVJsSAPC5Y%2FktsSogusrhfjxNzG7NFzNkhlt4WeXl8WhiVf1676I46rqo%2B0pHb44yL%2Bx%2F%2FDaX2tyyoQtgiA22cZZ6D6TwC4eApQDJvHvhLRo2BkFBhmTwF2Mb%2FbOWeO%2BzIfoC703T%2FyiaH4UX%2F8%2Bg%2BdeB99cg7r2vDffFOVlwZT2bC5J3g3Lu%2B3CL%2Bkw6nNvgAqvhctjp%2BT5XrrNbn8Zdf01Bvl4Zt6jRAgkVOm6W4ypXLYvHvorCWuZkF%2FAjG7cP%2BqxIV%2F052YmzsEmlBXF2FseYQa8krKJBXqccRw3%2BSt%2Bp0czmAZl1pjDxPb7I8iWfklRAIuLmDjYC9AAwltkGD6HaNx5HiuPU38%2FOA5mlcjnI11MqMJahSjvDmalO9FC79CTApSRHh2rZpPvgwjQeYj0EbeJavGZZ3zc2%2BzRyevIPrOp21TMVbepkJuDh0hNSsNRgUqoMYlfEVxArsVGv9dPPj0%2FBWuZkDVEFQ7EZ6hLHLlyErNYBCCakXf2EC0fsDhqkqXDl5h%2FcsQ3d7ZjWjTGfRdZNK%2BAI%2FXYSkFugN6r0LMaFqq867t2bShlhQgIz4YYKBnDk8WSIljN4ZnBknFi4RxWpy66U3%2BjCqHPYLP2hdlzaVATMwcbSZ%2BJKGpZ7owIFv3AM6WF8nltBJ%2FqAT8FBnijfHZhi6gwuuqPXy3BooDpnY%2B4F7hH3ilInLgi9T1IjTc73FiG11byMxD5Sg7w14p3uu5cbyWpcFkaP9ommZzu5bemVNg5mVKROLgprZxqSr4mOLq2CJdu4ZhDGwmZSgTVMf8TxXdwMx7M2352wVWJFaYaxvZuOfJAE9FwCaDOUcr%2BTA00WCFcdT2xULkwGIyJ0HJi1RmaKkdXnNMI5FeXt9fOMxgnycJ0YstNxy6XnqhdnY5G2gwlIqrpcTwEmcroWXkOqlQ0b8WAS85XhACI3rpHOjMXtfNFGMkzZ06Lz%2B3BxeZ%2BsBnNAuCYpeJSL3Htf%2BElN%2Ba2E1QiIieWG61dsr7eiru3pSWsnEE2T%2Bry47o25MX62sLkXTdR1Zc8HTsmucCiaygbHNGCSAtAbsjjtXC52nepFmqZEUcpbuWZfvTNoEejv8SjGmTJTmMzknNngxbnzSbQxb%2FWdv46ca9sOh6nMpNtPgzgpXtPhlh9Nu6S%2FpeShynemapDzTFr0QBjgOB3HYz%2B396E5bGWIeSY5ckiShN8tuPe48UeOiDVCeazzpTY8s5CfrgtVO0WfSXv29Q3R6pJQmNZJvl4YkJVZ%2FPb973%2B8%2FWvqD%2BpqiKoh2L5R93%2FT%2FzQNP8Ar%2F%2F%2FYBKsoGOoODQt0S0to2Dc%2Fxq74nQgxHJAkgW9lFynsCGxHCGBHELjAERy%2FFfhgT%2FHcVuyKn48m2fYyb%2B0OxmxdTroRFHwR%2FUa%2BMXHoERjGRDhNYgSNexRkCSYgMAYGeEjGIYZRNI3hOMS2O3o%2BhH5A4UG4ZdyIjiF4dWfpZiX487%2B%2BvRXNr%2B7phXpD%2Fqvp%2Bu88%2FPbCwV%2B%2BeElkZbMxNq%2F8%2FZ9uCYP%2BM2uyaq3Hz6Au0U0EvRwsL8Eqxrwrhg6ZT4ZjYxX7Wxd%2B%2FfhhSKpwMzhV%2F%2FHjPSuj7Ov9F7TFVMDGcUx9xGQcfFA%2BiD82I%2BgPEL4YtEdhJPGehbG3qZD2IretLr3g6z1rNpCAnwD7hBj%2ByYL3cRMwr8o2X%2Fdf2PvQ%2F697dlGbvfZxFS7mxtyUbczxpdbclL5tzvjllG9%2FGRwUWZD%2FJ5ODIv83Jn8mWfz%2FyuztOgevAqiPBjVbonD3V9SrdRj9zKrhJ%2FZtm9nX5W2Lby%2BJhMrziyj86dd1EXnVz6Ebo1dkDf3rn4CtOwfbz%2FaB2xVCuJGv9wf2%2B%2FXxmtzkh99NPcHgGM6QcGv%2Bm%2Fy1jc29n39VEp9%2BV8991L2OxFK8SrQX8StW3%2F78B6ENMoZ%2BEAAA";
        // String sig = "XalwhQZHtDQy57XQm6sOmJEQv9Lk5B0Bl000eIVYPJ3ifA2TVhTqIjvBm9ecZN%2FALleIU2Iw0H1%2Frz1zY%2FPpwKrejff1QcSzWDCH7rE0AJndxYOnhb%2BMrgBD%2B1NaokdPWFo4xkMkUqDLbl4PInsW%2F3cprh5k67e3V1g0%2BdLo5UCZVrpbFMU328EMdNHPgpoG7NFnkZ1EvwFoNmLqP9ww9Wcw2M1m4qe%2FBRRluY3M52pLVbyVePSGTzmG5G554ukcrFwDJpBZaFbmqDahZRO4rrTXabzwl1UkJ%2FNn2j5iGWfMDY8rNJYfIww2Gi0vMd5o41g3%2Bu%2BlPFCb7iZcx6gDBXSCNi%2FjjVu2xndBvQ%2BpDyAMcGMCDF1SqH%2FfMXf2%2Fv1A0ubgkGRO1srBu5GzNkqjSaG4Rux%2FkfEnlf2a1FT7vhjfaE1pS2wdgZ6oq4cNtn86M8EmWChMF5mNm12wHyO77ZMnbuA2y2cjBq%2Bx8etMmWUGG7EB%2B5ZsRlPdw7GcM9am";
        String cnt = "https://www.baidu.com";
        String sig = "ZXQPjMsvbbIATpb6YFz62VusX73TBtb465/cfeUdrQE1VRHb1I1BPIQRfkN2XdC2N4SDJ86JqZ9WwLJd6Zs6W3AJ1JqaPwmFzzrlksExcE7XACGHoq/J3siveQusbCnJ7z64r1qyLFKBjNQ0bgvR5deQ50/63H/pt+OOsHFEBwghA16QIBg8DSRVXRPnVCm0q4/VzryYeRleZKbFQH2u44HzsJAmScJK9flwH9N4u2fWRzG03JmOykvLtvpoL2P2kTQb/lfPP/J13saS1iOQ4k981jg/FldcmIbSQ8E8AQIjJDo1KRFw7CHkTve3h7RqfM7ykj41PTq8s/VUygB/ama+j4tU9CBLEPmEUKSyHU6JPkPmv+UuPyDkYe53SSH48jLzekFjJgLJr0eSkjdhZXm8apN2bXzZ/gsLqPkOBFfpg6XJ7DBmIRu+fJWa6F8TP5VxTd9vzBcAOdy0L9z0KeoLoejtyEmJwvVmVfF+bIJ1R0rS5DNbc9qSiVeoco83";
        // String sig = "QTAaAFPmiEtCsKLwCoekSCwSbEXa8CP5RzcXc3nb2naUaQNswjCMD5wlriS1W5upuC+ZQKge2atpj2ARMJ16y2AQ0V/b7L4ARsmDmfT0MczA5jHtCM9kKtyIZgMUUZqCTZLcmd80Yms6u3nZHY5MN/Qd45Tqt/F1IyLooMw05n+3kWKw3GmpwdkL2OVeBTB+7DnJHpsNH0eqkomhY3vNzB8GMlcQ/X6Ce5C500fhprBG84xpXIpKoVD5vgaH61C5ABRihnGHX2uhflyoHsT21TgJNNdMHGWULgj/6gbaLaHzK8XIoPLesDylv1vlt1hpcfNsxyGwvD2kGJjcVHoKbqkBVCDa82sEkuLcXhlzTsEecXZC16/UgGlej7yFlSFRl36Adkyuhex8iZSxuHycBNYSzJqZTUZb9EhwB0ikOMScumT5k4VsembsMo9I1k71b++fghnliGjWBHQJtULLbYTbh2ioJftx26BZtzTanGBzQVNVwos2Yd93YM0/ljt1";

        boolean ret = false;
        try {
            ret = this.verify(cnt, sig);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        Log.d(TAG, "onCreate: " + ret);

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

        try {
            if (check(cnt_sha256, sig, false)) {
                return true;
            }
            return check(cnt_sha256, sig, true);
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
