/*
 * md5.cpp https://github.com/ulwanski/md5.git
 */
#include <jni.h>
#include <string>
#include <Android/log.h>
#include <assert.h>
#include <unistd.h>
#include "md5.h"
#include "aes_utils.h"
#include "tools.h"
#include "junk.h"
#include <fstream>

#define TAG "easyso1"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,TAG ,__VA_ARGS__) // 定义LOGD类型
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,TAG ,__VA_ARGS__) // 定义LOGI类型
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,TAG ,__VA_ARGS__) // 定义LOGW类型
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,TAG ,__VA_ARGS__) // 定义LOGE类型
#define LOGF(...) __android_log_print(ANDROID_LOG_FATAL,TAG ,__VA_ARGS__) // 定义LOGF类型
#define NELEM(x) ((int) (sizeof(x) / sizeof((x)[0])))

#ifndef HAVE_OPENSSL

#define F(x, y, z)   ((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)   ((y) ^ ((z) & ((x) ^ (y))))
#define H(x, y, z)   ((x) ^ (y) ^ (z))
#define I(x, y, z)   ((y) ^ ((x) | ~(z)))
#define STEP(f, a, b, c, d, x, t, s) \
        (a) += f((b), (c), (d)) + (x) + (t); \
        (a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s)))); \
        (a) += (b);

#if defined(__i386__) || defined(__x86_64__) || defined(__vax__)
#define SET(n) \
            (*(MD5_u32 *)&ptr[(n) * 4])
#define GET(n) \
            SET(n)
#else
#define SET(n) \
            (ctx->block[(n)] = \
            (MD5_u32)ptr[(n) * 4] | \
            ((MD5_u32)ptr[(n) * 4 + 1] << 8) | \
            ((MD5_u32)ptr[(n) * 4 + 2] << 16) | \
            ((MD5_u32)ptr[(n) * 4 + 3] << 24))
#define GET(n) \
            (ctx->block[(n)])
#endif

typedef unsigned int MD5_u32;

typedef struct {
    MD5_u32 lo, hi;
    MD5_u32 a, b, c, d;
    unsigned char buffer[64];
    MD5_u32 block[16];
} MD5_CTX;

static void MD5_Init(MD5_CTX *ctx);

static void MD5_Update(MD5_CTX *ctx, const void *data, unsigned long size);

static void MD5_Final(unsigned char *result, MD5_CTX *ctx);

static const void *body(MD5_CTX *ctx, const void *data, unsigned long size) {
    const unsigned char *ptr;
    MD5_u32 a, b, c, d;
    MD5_u32 saved_a, saved_b, saved_c, saved_d;

    ptr = (const unsigned char *) data;

    a = ctx->a;
    b = ctx->b;
    c = ctx->c;
    d = ctx->d;

    do {
        saved_a = a;
        saved_b = b;
        saved_c = c;
        saved_d = d;

        STEP(F, a, b, c, d, SET(0), 0xd76aa478, 7)
        STEP(F, d, a, b, c, SET(1), 0xe8c7b756, 12)
        STEP(F, c, d, a, b, SET(2), 0x242070db, 17)
        STEP(F, b, c, d, a, SET(3), 0xc1bdceee, 22)
        STEP(F, a, b, c, d, SET(4), 0xf57c0faf, 7)
        STEP(F, d, a, b, c, SET(5), 0x4787c62a, 12)
        STEP(F, c, d, a, b, SET(6), 0xa8304613, 17)
        STEP(F, b, c, d, a, SET(7), 0xfd469501, 22)
        STEP(F, a, b, c, d, SET(8), 0x698098d8, 7)
        STEP(F, d, a, b, c, SET(9), 0x8b44f7af, 12)
        STEP(F, c, d, a, b, SET(10), 0xffff5bb1, 17)
        STEP(F, b, c, d, a, SET(11), 0x895cd7be, 22)
        STEP(F, a, b, c, d, SET(12), 0x6b901122, 7)
        STEP(F, d, a, b, c, SET(13), 0xfd987193, 12)
        STEP(F, c, d, a, b, SET(14), 0xa679438e, 17)
        STEP(F, b, c, d, a, SET(15), 0x49b40821, 22)
        STEP(G, a, b, c, d, GET(1), 0xf61e2562, 5)
        STEP(G, d, a, b, c, GET(6), 0xc040b340, 9)
        STEP(G, c, d, a, b, GET(11), 0x265e5a51, 14)
        STEP(G, b, c, d, a, GET(0), 0xe9b6c7aa, 20)
        STEP(G, a, b, c, d, GET(5), 0xd62f105d, 5)
        STEP(G, d, a, b, c, GET(10), 0x02441453, 9)
        STEP(G, c, d, a, b, GET(15), 0xd8a1e681, 14)
        STEP(G, b, c, d, a, GET(4), 0xe7d3fbc8, 20)
        STEP(G, a, b, c, d, GET(9), 0x21e1cde6, 5)
        STEP(G, d, a, b, c, GET(14), 0xc33707d6, 9)
        STEP(G, c, d, a, b, GET(3), 0xf4d50d87, 14)
        STEP(G, b, c, d, a, GET(8), 0x455a14ed, 20)
        STEP(G, a, b, c, d, GET(13), 0xa9e3e905, 5)
        STEP(G, d, a, b, c, GET(2), 0xfcefa3f8, 9)
        STEP(G, c, d, a, b, GET(7), 0x676f02d9, 14)
        STEP(G, b, c, d, a, GET(12), 0x8d2a4c8a, 20)
        STEP(H, a, b, c, d, GET(5), 0xfffa3942, 4)
        STEP(H, d, a, b, c, GET(8), 0x8771f681, 11)
        STEP(H, c, d, a, b, GET(11), 0x6d9d6122, 16)
        STEP(H, b, c, d, a, GET(14), 0xfde5380c, 23)
        STEP(H, a, b, c, d, GET(1), 0xa4beea44, 4)
        STEP(H, d, a, b, c, GET(4), 0x4bdecfa9, 11)
        STEP(H, c, d, a, b, GET(7), 0xf6bb4b60, 16)
        STEP(H, b, c, d, a, GET(10), 0xbebfbc70, 23)
        STEP(H, a, b, c, d, GET(13), 0x289b7ec6, 4)
        STEP(H, d, a, b, c, GET(0), 0xeaa127fa, 11)
        STEP(H, c, d, a, b, GET(3), 0xd4ef3085, 16)
        STEP(H, b, c, d, a, GET(6), 0x04881d05, 23)
        STEP(H, a, b, c, d, GET(9), 0xd9d4d039, 4)
        STEP(H, d, a, b, c, GET(12), 0xe6db99e5, 11)
        STEP(H, c, d, a, b, GET(15), 0x1fa27cf8, 16)
        STEP(H, b, c, d, a, GET(2), 0xc4ac5665, 23)
        STEP(I, a, b, c, d, GET(0), 0xf4292244, 6)
        STEP(I, d, a, b, c, GET(7), 0x432aff97, 10)
        STEP(I, c, d, a, b, GET(14), 0xab9423a7, 15)
        STEP(I, b, c, d, a, GET(5), 0xfc93a039, 21)
        STEP(I, a, b, c, d, GET(12), 0x655b59c3, 6)
        STEP(I, d, a, b, c, GET(3), 0x8f0ccc92, 10)
        STEP(I, c, d, a, b, GET(10), 0xffeff47d, 15)
        STEP(I, b, c, d, a, GET(1), 0x85845dd1, 21)
        STEP(I, a, b, c, d, GET(8), 0x6fa87e4f, 6)
        STEP(I, d, a, b, c, GET(15), 0xfe2ce6e0, 10)
        STEP(I, c, d, a, b, GET(6), 0xa3014314, 15)
        STEP(I, b, c, d, a, GET(13), 0x4e0811a1, 21)
        STEP(I, a, b, c, d, GET(4), 0xf7537e82, 6)
        STEP(I, d, a, b, c, GET(11), 0xbd3af235, 10)
        STEP(I, c, d, a, b, GET(2), 0x2ad7d2bb, 15)
        STEP(I, b, c, d, a, GET(9), 0xeb86d391, 21)

        a += saved_a;
        b += saved_b;
        c += saved_c;
        d += saved_d;

        ptr += 64;
    } while (size -= 64);

    ctx->a = a;
    ctx->b = b;
    ctx->c = c;
    ctx->d = d;

    return ptr;
}

void MD5_Init(MD5_CTX *ctx) {
    ctx->a = 0x67452301;
    ctx->b = 0xefcdab89;
    ctx->c = 0x98badcfe;
    ctx->d = 0x10325476;

    ctx->lo = 0;
    ctx->hi = 0;
}

void MD5_Update(MD5_CTX *ctx, const void *data, unsigned long size) {
    MD5_u32 saved_lo;
    unsigned long used, free;

    saved_lo = ctx->lo;
    if ((ctx->lo = (saved_lo + size) & 0x1fffffff) < saved_lo)
        ctx->hi++;
    ctx->hi += size >> 29;
    used = saved_lo & 0x3f;

    if (used) {
        free = 64 - used;
        if (size < free) {
            memcpy(&ctx->buffer[used], data, size);
            return;
        }

        memcpy(&ctx->buffer[used], data, free);
        data = (unsigned char *) data + free;
        size -= free;
        body(ctx, ctx->buffer, 64);
    }

    if (size >= 64) {
        data = body(ctx, data, size & ~(unsigned long) 0x3f);
        size &= 0x3f;
    }

    memcpy(ctx->buffer, data, size);
}

void MD5_Final(unsigned char *result, MD5_CTX *ctx) {
    unsigned long used, free;
    used = ctx->lo & 0x3f;
    ctx->buffer[used++] = 0x80;
    free = 64 - used;

    if (free < 8) {
        memset(&ctx->buffer[used], 0, free);
        body(ctx, ctx->buffer, 64);
        used = 0;
        free = 64;
    }

    memset(&ctx->buffer[used], 0, free - 8);

    ctx->lo <<= 3;
    ctx->buffer[56] = ctx->lo;
    ctx->buffer[57] = ctx->lo >> 8;
    ctx->buffer[58] = ctx->lo >> 16;
    ctx->buffer[59] = ctx->lo >> 24;
    ctx->buffer[60] = ctx->hi;
    ctx->buffer[61] = ctx->hi >> 8;
    ctx->buffer[62] = ctx->hi >> 16;
    ctx->buffer[63] = ctx->hi >> 24;
    body(ctx, ctx->buffer, 64);
    result[0] = ctx->a;
    result[1] = ctx->a >> 8;
    result[2] = ctx->a >> 16;
    result[3] = ctx->a >> 24;
    result[4] = ctx->b;
    result[5] = ctx->b >> 8;
    result[6] = ctx->b >> 16;
    result[7] = ctx->b >> 24;
    result[8] = ctx->c;
    result[9] = ctx->c >> 8;
    result[10] = ctx->c >> 16;
    result[11] = ctx->c >> 24;
    result[12] = ctx->d;
    result[13] = ctx->d >> 8;
    result[14] = ctx->d >> 16;
    result[15] = ctx->d >> 24;
    memset(ctx, 0, sizeof(*ctx));
}

#else
#include <openssl/md5.h>
#endif


using namespace std;

/* Return Calculated raw result(always little-endian), the size is always 16 */
void md5bin(const void *dat, size_t len, unsigned char out[16]) {
    MD5_CTX c;
    MD5_Init(&c);
    MD5_Update(&c, dat, len);
    MD5_Final(out, &c);
}

static char hb2hex(unsigned char hb) {
    hb = hb & 0xF;
    return hb < 10 ? '0' + hb : hb - 10 + 'a';
}

string md5file(const char *filename) {
    std::FILE *file = std::fopen(filename, "rb");
    string res = md5file(file);
    std::fclose(file);
    return res;
}

string md5file(std::FILE *file) {

    MD5_CTX c;
    MD5_Init(&c);

    char buff[BUFSIZ];
    unsigned char out[16];
    size_t len = 0;
    while ((len = std::fread(buff, sizeof(char), BUFSIZ, file)) > 0) {
        MD5_Update(&c, buff, len);
    }
    MD5_Final(out, &c);

    string res;
    for (size_t i = 0; i < 16; ++i) {
        res.push_back(hb2hex(out[i] >> 4));
        res.push_back(hb2hex(out[i]));
    }
    return res;
}

string md5(const void *dat, size_t len) {
    string res;
    unsigned char out[16];
    md5bin(dat, len, out);
    for (size_t i = 0; i < 16; ++i) {
        res.push_back(hb2hex(out[i] >> 4));
        res.push_back(hb2hex(out[i]));
    }
    return res;
}

std::string md5(std::string dat) {
    return md5(dat.c_str(), dat.length());
}

/* Generate shorter md5sum by something like base62 instead of base16 or base10. 0~61 are represented by 0-9a-zA-Z */
string md5sum6(const void *dat, size_t len) {
    static const char *tbl = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    string res;
    unsigned char out[16];
    md5bin(dat, len, out);
    for (size_t i = 0; i < 6; ++i) {
        res.push_back(tbl[out[i] % 62]);
    }
    return res;
}

std::string md5sum6(std::string dat) {
    return md5sum6(dat.c_str(), dat.length());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_tesla_easyso1_MainActivity_stringFromJNI(JNIEnv *env, jobject thiz) {
    // for
    int i;
    for (i = 0; i < 10; i++) {
        printf("%d", i);
        LOGD("current i is %d", i);
    }

    // md5
    string ret = md5("123456");
    LOGD("%s", ret.c_str());  // e10adc3949ba59abbe56e057f20f883e

    std::string hello = "Hello from JNI.";
    return env->NewStringUTF(hello.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_tesla_easyso1_MainActivity_method01(JNIEnv *env, jclass clazz, jstring str_) {
    // TODO: implement method01()
    if (str_ == nullptr) return nullptr;

    const char *str = env->GetStringUTFChars(str_, JNI_FALSE);
    char *result = AES_128_CBC_PKCS5_Encrypt(str);

    env->ReleaseStringUTFChars(str_, str);

    jstring jResult = getJString(env, result);
    free(result);

    return jResult;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_tesla_easyso1_MainActivity_method02(JNIEnv *env, jclass clazz, jstring str_) {
    // TODO: implement method02()
    if (str_ == nullptr) return nullptr;

    const char *str = env->GetStringUTFChars(str_, JNI_FALSE);
    char *result = AES_128_CBC_PKCS5_Decrypt(str);

    env->ReleaseStringUTFChars(str_, str);

    jstring jResult = getJString(env, result);
    free(result);

    return jResult;
}

/**
 * debug项目 观察日志
 */
bool function_check_tracerPID() {
    bool b = false;
    int pid = getpid();
    std::string file_name = "/proc/pid/status";
    std::string line;
    file_name.replace(file_name.find("pid"), 3, std::to_string(pid));
    LOGE("replace file name => %s", file_name.c_str());
    std::ifstream myfile(file_name, std::ios::in);
    if (myfile.is_open()) {
        while (getline(myfile, line)) {
            size_t TracerPid_pos = line.find("TracerPid");
            if (TracerPid_pos == 0) {
                line = line.substr(line.find(":") + 1);
                LOGE("file line => %s", line.c_str());
                if (std::stoi(line.c_str()) != 0) {
                    LOGE("trace pid => %s, i want to exit.", line.c_str());
                    b = true;
//                    kill(pid, 9);
                    break;
                }
            }
        }
        myfile.close();
    }
    return b;
}

/**
 * c++拿设备指纹
 */
bool system_getproperty_check() {
    char man[256], mod[156];
    /* A length 0 value indicates that the property is not defined */
    int lman = __system_property_get("ro.product.manufacturer", man);
    int lmod = __system_property_get("ro.product.model", mod);
    int len = lman + lmod;
    char *pname = NULL;
    if (len > 0) {
        pname = static_cast<char *>(malloc(len + 2));
        snprintf(pname, len + 2, "%s/%s", lman > 0 ? man : "", lmod > 0 ? mod : "");
    }

    bool b = false;
    if (strstr(pname, "Google"))b = true;
    LOGE("[roysue device]: [%s] result is => %d\n", pname ? pname : "N/A", b);
    return b;
}

jstring ngis(JNIEnv *env, jclass jclazz, jstring jstr) {
    // 环境检测
    std::string sign = "REAL";

    // Java层反射拿设备指纹
    jclass Build = env->FindClass("android/os/Build");
    jfieldID FINGERPRINT = env->GetStaticFieldID(Build, "FINGERPRINT", "Ljava/lang/String;");
    jstring FINGERPRINTValue = jstring(env->GetStaticObjectField(Build, FINGERPRINT));
    // google/blueline/blueline:9/PQ3A.190801.002/5670241:user/release-keys
    // 此处可综合判断aosp google ...
    LOGD("FINGERPRINTValue %s", env->GetStringUTFChars(FINGERPRINTValue, JNI_FALSE));
    if (function_check_tracerPID() ||system_getproperty_check() ||
        strstr(env->GetStringUTFChars(FINGERPRINTValue, JNI_FALSE), "google")) {
        sign = "FAKE";
    }

    // Concatenate two jstrings using StringBuilder Java
//    jclass cls_StringBuilder = env->FindClass("java/lang/StringBuilder");
//    jmethodID mid_StringBuilder_init = env->GetMethodID(cls_StringBuilder, "<init>", "()V");
//    jobject obj_StringBuilder = env->NewObject(cls_StringBuilder, mid_StringBuilder_init);
//    jmethodID mid_StringBuilder_append = env->GetMethodID(cls_StringBuilder, "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;");
//
//    obj_StringBuilder = env->CallObjectMethod(obj_StringBuilder, mid_StringBuilder_append, jstr);
//    obj_StringBuilder = env->CallObjectMethod(obj_StringBuilder, mid_StringBuilder_append, FINGERPRINTValue);
//
//    jstring ret = (jstring)env->CallObjectMethod(obj_StringBuilder, env->GetMethodID(cls_StringBuilder, "toString", "()Ljava/lang/String;"));

    // Concatenate two jstrings using StringBuilder C++
    char *cstr = const_cast<char *>(env->GetStringUTFChars(jstr, JNI_FALSE));
    strcat(cstr, sign.c_str());
    LOGD("cstr %s", cstr);

    // 直接拼接返回明文 str + REAL/FAKE
    // return env->NewStringUTF(cstr);

    // 拼接结果进行AES加密返回 服务器解密判断后可返回错误数据 AES(str + REAL/FAKE)
    // 再次对AES的结果进行md5加密拼接 服务器判断后32位与前部分一致性 --> sign被篡改或错误生成直接识别
    // AES(str + REAL/FAKE) + md5(AES(str + REAL/FAKE))
    // 优势: 1.篡改sign非法sign立即识别 2.环境检测 aosp + google 识别
    // 通过android.os.Build反射获取属性 frida随便就可以hook绕过 所以需要从c++拿设备指纹
    char *aes_ret = AES_128_CBC_PKCS5_Encrypt(cstr);
    LOGD("aes_ret %s", aes_ret);
    string md5Ret = md5(aes_ret);
    const char *md5_ret = md5Ret.c_str();
    LOGD("md5_ret %s", md5_ret);

    strcat(aes_ret, md5_ret);
    LOGD("aes_ret+md5_ret %s", aes_ret);

    jstring aesRet = getJString(env, aes_ret);
    return aesRet;
}

static JNINativeMethod method_table[] = {
        {"sign", "(Ljava/lang/String;)Ljava/lang/String;", (void *) ngis},
};

static int registerMethods(JNIEnv *env, const char *className,
                           JNINativeMethod *gMethods, int numMethods) {
    jclass clazz = env->FindClass(className);
    if (clazz == nullptr) {
        return JNI_FALSE;
    }
    if (env->RegisterNatives(clazz, gMethods, numMethods) < 0) {
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    _JUNK_FUN_0

    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    assert(env != nullptr);

    // 注册native方法
    if (!registerMethods(env, "com/tesla/easyso1/MainActivity", method_table,
                         NELEM(method_table))) {
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}