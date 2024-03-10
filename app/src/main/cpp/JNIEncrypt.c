#include <jni.h>
#include "aes.h"
#include "logger.h"
#include <string.h>
#include <stdbool.h>
//log定义
#define  LOG  "JINTAO_SECURITY" // 这个是自定义的LOG的TAG
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,LOG,__VA_ARGS__)

const char HexCode[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

//签名文件的 sha1
#define RELEASE_SIGN "D827AB0C12F4766195562068EA651B458D4EAC67"
//定义你的包名
#define APP_PACKAGE "com.jintao.secret"

static bool isInit = false;

jobject getApplication(JNIEnv *env);

#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")

#define CBC 1
#define ECB 1

jstring charToJstring(JNIEnv *envPtr, char *src) {
    JNIEnv env = *envPtr;

    jsize len = strlen(src);
    jclass clsstring = env->FindClass(envPtr, "java/lang/String");
    jstring strencode = env->NewStringUTF(envPtr, "UTF-8");
    jmethodID mid = env->GetMethodID(envPtr, clsstring, "<init>",
                                     "([BLjava/lang/String;)V");
    jbyteArray barr = env->NewByteArray(envPtr, len);
    env->SetByteArrayRegion(envPtr, barr, 0, len, (jbyte *) src);

    return (jstring) env->NewObject(envPtr, clsstring, mid, barr, strencode);
}

char* getSecretKey() {
    int n = 0;
    char s[23];
    s[n++] = 'X';
    s[n++] = 'H';
    s[n++] = 'W';
    s[n++] = 'M';
    s[n++] = 'W';
    s[n++] = 'P';
    s[n++] = 'K';
    s[n++] = 'F';
    s[n++] = 'Y';
    s[n++] = 'M';
    s[n++] = 'R';
    s[n++] = 'w';
    s[n++] = 'b';
    s[n++] = 'm';
    s[n++] = 'W';
    s[n++] = 'R';
    s[n++] = 'B';
    s[n++] = '1';
    s[n++] = 'g';
    s[n++] = '7';
    s[n++] = 'h';
    s[n++] = 'm';
    s[n++] = 'l';
    char *encode_str = s + 1;
    return b64_decode(encode_str, strlen(encode_str));
}

JNIEXPORT jstring JNICALL Java_com_jintao_secret_EncrypyUtils_encode(JNIEnv *env, jobject instance,jstring str_) {
    if (!isInit) {
        return (*env)->NewStringUTF(env,"unknown");
    }
    uint8_t *AES_KEY = (uint8_t *) getSecretKey();
    const char *in = (*env)->GetStringUTFChars(env, str_, JNI_FALSE);
    char *baseResult = AES_128_ECB_PKCS5Padding_Encrypt(in, AES_KEY);
    (*env)->ReleaseStringUTFChars(env, str_, in);
//    return (*env)->NewStringUTF(env, baseResult);
    jstring result = (*env)->NewStringUTF(env, baseResult);
    free(baseResult);
    free(AES_KEY);
    return result;
}


JNIEXPORT jstring JNICALL Java_com_jintao_secret_EncrypyUtils_decode(JNIEnv *env, jobject instance, jstring str_) {
    if (!isInit) {
        return (*env)->NewStringUTF(env,"unknown");
    }
    uint8_t *AES_KEY = (uint8_t *) getSecretKey();
    const char *str = (*env)->GetStringUTFChars(env, str_, JNI_FALSE);
    char *desResult = AES_128_ECB_PKCS5Padding_Decrypt(str, AES_KEY);
    (*env)->ReleaseStringUTFChars(env, str_, str);
    //不用系统自带的方法NewStringUTF是因为如果desResult是乱码,会抛出异常
    jstring result = charToJstring(env,desResult);
    free(desResult);
    free(AES_KEY);
    return result;
}

JNIEXPORT jboolean JNICALL Java_com_jintao_secret_EncrypyUtils_init(JNIEnv *env) {
    if (isInit) {
        return true;
    }
    jobject application = getApplication(env);
    if (application == NULL) {
        return false;
    }
    jclass activity = (*env)->GetObjectClass(env,application);
    // 得到 getPackageManager 方法的 ID
    jmethodID methodID_func = (*env)->GetMethodID(env,activity, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    // 获得PackageManager对象
    jobject packageManager = (*env)->CallObjectMethod(env,application, methodID_func);
    jclass packageManagerclass = (*env)->GetObjectClass(env,packageManager);

    //得到 getPackageName 方法的 ID
    jmethodID methodID_pack = (*env)->GetMethodID(env,activity, "getPackageName", "()Ljava/lang/String;");
    //获取包名
    jstring package_name = (jstring)((*env)->CallObjectMethod(env,application, methodID_pack));
    const char *pkgName = (*env)->GetStringUTFChars(env,package_name, NULL);
    if(strcmp(pkgName, APP_PACKAGE) != 0) {
        return false;
    }
    // 得到 getPackageInfo 方法的 ID
    jmethodID methodID_pm = (*env)->GetMethodID(env,packageManagerclass, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    // 获得应用包的信息
    jobject package_info = (*env)->CallObjectMethod(env,packageManager, methodID_pm, package_name, 64);

    // 获得 PackageInfo 类
    jclass package_infoclass = (*env)->GetObjectClass(env,package_info);
    // 获得签名数组属性的 ID
    jfieldID fieldID_signatures = (*env)->GetFieldID(env,package_infoclass, "signatures", "[Landroid/content/pm/Signature;");
    // 得到签名数组，待修改
    jobject signatur = (*env)->GetObjectField(env,package_info, fieldID_signatures);
    jobjectArray  signatures = (jobjectArray)(signatur);

    // 得到签名
    jobject signature = (*env)->GetObjectArrayElement(env,signatures, 0);
    // 获得 Signature 类，待修改
    jclass signature_clazz = (*env)->GetObjectClass(env,signature);
    //---获得签名byte数组
    jmethodID tobyte_methodId = (*env)->GetMethodID(env,signature_clazz, "toByteArray", "()[B");
    jbyteArray signature_byte = (jbyteArray) (*env)->CallObjectMethod(env,signature, tobyte_methodId);

    //把byte数组转成流
    jclass byte_array_input_class = (*env)->FindClass(env,"java/io/ByteArrayInputStream");
    jmethodID init_methodId = (*env)->GetMethodID(env,byte_array_input_class, "<init>", "([B)V");
    jobject byte_array_input = (*env)->NewObject(env,byte_array_input_class, init_methodId, signature_byte);

    //实例化X.509
    jclass certificate_factory_class = (*env)->FindClass(env,"java/security/cert/CertificateFactory");
    jmethodID certificate_methodId = (*env)->GetStaticMethodID(env,certificate_factory_class, "getInstance", "(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;");
    jstring x_509_jstring = (*env)->NewStringUTF(env,"X.509");
    jobject cert_factory = (*env)->CallStaticObjectMethod(env,certificate_factory_class, certificate_methodId, x_509_jstring);

    //certFactory.generateCertificate(byteIn);
    jmethodID certificate_factory_methodId = (*env)->GetMethodID(env,certificate_factory_class, "generateCertificate", ("(Ljava/io/InputStream;)Ljava/security/cert/Certificate;"));
    jobject x509_cert = (*env)->CallObjectMethod(env,cert_factory, certificate_factory_methodId, byte_array_input);

    jclass x509_cert_class = (*env)->GetObjectClass(env,x509_cert);
    jmethodID x509_cert_methodId = (*env)->GetMethodID(env,x509_cert_class, "getEncoded", "()[B");
    jbyteArray cert_byte = (jbyteArray)(*env)->CallObjectMethod(env,x509_cert, x509_cert_methodId);

    //MessageDigest.getInstance("SHA1")
    jclass message_digest_class = (*env)->FindClass(env,"java/security/MessageDigest");
    jmethodID methodId = (*env)->GetStaticMethodID(env,message_digest_class, "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    //如果取SHA1则输入SHA1
    jstring sha1_jstring=(*env)->NewStringUTF(env,"SHA1");
//    jstring sha1_jstring = (*env)->NewStringUTF(env,"MD5");
    jobject sha1_digest = (*env)->CallStaticObjectMethod(env,message_digest_class, methodId, sha1_jstring);
    //sha1.digest (certByte)
    methodId = (*env)->GetMethodID(env,message_digest_class, "digest", "([B)[B");
    jbyteArray sha1_byte = (jbyteArray)(*env)->CallObjectMethod(env,sha1_digest, methodId, cert_byte);
    //toHexString
    jsize array_size = (*env)->GetArrayLength(env,sha1_byte);
    jbyte *sha1 = (*env)->GetByteArrayElements(env,sha1_byte, NULL);
    char hex_sha[array_size * 2 + 1];
    int i;
    for (i = 0; i < array_size; ++i)
    {
        hex_sha[2 * i] = HexCode[((unsigned char)sha1[i]) / 16];
        hex_sha[2 * i + 1] = HexCode[((unsigned char)sha1[i]) % 16];
    }
    hex_sha[array_size * 2] = '\0';
//    LOGE("hex_sha: %s\n", hex_sha);
    if(strcmp(hex_sha, RELEASE_SIGN) == 0)
    {
        isInit = true;
        return true;
    }
    else
    {
        return false;
    }
}

jobject getApplication(JNIEnv *env) {
    jobject application = NULL;
    jclass activity_thread_clz = (*env)->FindClass(env,"android/app/ActivityThread");
    if (activity_thread_clz != NULL) {
        jmethodID currentApplication = (*env)->GetStaticMethodID(env,
                activity_thread_clz, "currentApplication", "()Landroid/app/Application;");
        if (currentApplication != NULL) {
            application = (*env)->CallStaticObjectMethod(env,activity_thread_clz, currentApplication);
        } else {
            LOGE("Cannot find method: currentApplication() in ActivityThread.");
        }
        (*env)->DeleteLocalRef(env,activity_thread_clz);
    } else {
        LOGE("Cannot find class: android.app.ActivityThread");
    }

    return application;
}