/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2017-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <android/log.h>


#define TAG "WireGuard/JNI"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
struct go_string { const char *str; long n; };
extern int wgTurnOn(struct go_string ifname, int tun_fd, struct go_string settings,struct go_string scramble,  uintptr_t callback);
extern void wgTurnOff(int handle);
extern int wgGetSocketV4(int handle);
extern int wgGetSocketV6(int handle);
extern char *wgGetConfig(int handle);
extern char *wgVersion();

// 添加全局变量
static JavaVM *jvm;
static jobject callbackObj;
static jmethodID statusCallbackMethod;

// 添加回调函数声明
void callbackAndroid(void* callback, int status, const char* message);

// 实现回调函数
void callbackAndroid(void* callback, int status, const char* message) {
    JNIEnv *env;
    (*jvm)->AttachCurrentThread(jvm, &env, NULL);

    jstring jmessage = (*env)->NewStringUTF(env, message);
    (*env)->CallVoidMethod(env, callbackObj, statusCallbackMethod, status, jmessage);
    (*env)->DeleteLocalRef(env, jmessage);

    (*jvm)->DetachCurrentThread(jvm);
}

// 添加外部函数声明
extern char* wgRequestSubIP(struct go_string ip, struct go_string publicKey, struct go_string uuid);




JNIEXPORT jstring JNICALL Java_com_wireguard_android_backend_GoBackend_wgRequestSubIP(
        JNIEnv *env, jclass c, jstring ip, jstring publicKey, jstring uuid)
{

    LOGD("开始请求子网 IP");

    const char *ip_str = (*env)->GetStringUTFChars(env, ip, 0);
    size_t ip_len = (*env)->GetStringUTFLength(env, ip);

    const char *publicKey_str = (*env)->GetStringUTFChars(env, publicKey, 0);
    size_t publicKey_len = (*env)->GetStringUTFLength(env, publicKey);

    const char *uuid_str = (*env)->GetStringUTFChars(env, uuid, 0);
    size_t uuid_len = (*env)->GetStringUTFLength(env, uuid);

    LOGD("参数: ip=%s, publicKey=%s, uuid=%s", ip_str, publicKey_str, uuid_str);

    char* result = wgRequestSubIP(
            (struct go_string){.str = ip_str, .n = ip_len},
            (struct go_string){.str = publicKey_str, .n = publicKey_len},
            (struct go_string){.str = uuid_str, .n = uuid_len}
    );

    (*env)->ReleaseStringUTFChars(env, ip, ip_str);
    (*env)->ReleaseStringUTFChars(env, publicKey, publicKey_str);
    (*env)->ReleaseStringUTFChars(env, uuid, uuid_str);

    if (!result){
        LOGD("请求子网 IP 失败");

        return NULL;
    }
    LOGD("请求子网 IP 成功: result=%s",result);

    jstring ret = (*env)->NewStringUTF(env, result);
    free(result);
    return ret;
}


JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgTurnOn(JNIEnv *env, jclass c, jstring ifname, jint tun_fd, jstring settings,jstring scramble, jobject callback )
{
    LOGD("打开wgTurnOn");

    // 保存 JVM 和回调相关信息
    (*env)->GetJavaVM(env, &jvm);
    callbackObj = (*env)->NewGlobalRef(env, callback);
    jclass callbackClass = (*env)->GetObjectClass(env, callback);
    statusCallbackMethod = (*env)->GetMethodID(env, callbackClass,
                                               "onStatusChanged", "(ILjava/lang/String;)V");


	const char *ifname_str = (*env)->GetStringUTFChars(env, ifname, 0);
	size_t ifname_len = (*env)->GetStringUTFLength(env, ifname);
	const char *settings_str = (*env)->GetStringUTFChars(env, settings, 0);
	size_t settings_len = (*env)->GetStringUTFLength(env, settings);
    const char *scramble_str = (*env)->GetStringUTFChars(env, scramble, 0);
    size_t scramble_len = (*env)->GetStringUTFLength(env, scramble);


	int ret = wgTurnOn((struct go_string){
		.str = ifname_str,
		.n = ifname_len
	}, tun_fd, (struct go_string){
		.str = settings_str,
		.n = settings_len
	},
                       (struct go_string){.str = scramble_str, .n = scramble_len},
                       (uintptr_t)&callbackAndroid);
	(*env)->ReleaseStringUTFChars(env, ifname, ifname_str);
	(*env)->ReleaseStringUTFChars(env, settings, settings_str);
    (*env)->ReleaseStringUTFChars(env, scramble, scramble_str);

    return ret;
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_GoBackend_wgTurnOff(JNIEnv *env, jclass c, jint handle)
{
	wgTurnOff(handle);

    if (callbackObj != NULL) {
        (*env)->DeleteGlobalRef(env, callbackObj);
        callbackObj = NULL;
    }
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgGetSocketV4(JNIEnv *env, jclass c, jint handle)
{
	return wgGetSocketV4(handle);
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgGetSocketV6(JNIEnv *env, jclass c, jint handle)
{
	return wgGetSocketV6(handle);
}

JNIEXPORT jstring JNICALL Java_com_wireguard_android_backend_GoBackend_wgGetConfig(JNIEnv *env, jclass c, jint handle)
{
	jstring ret;
	char *config = wgGetConfig(handle);
	if (!config)
		return NULL;
	ret = (*env)->NewStringUTF(env, config);
	free(config);
	return ret;
}

JNIEXPORT jstring JNICALL Java_com_wireguard_android_backend_GoBackend_wgVersion(JNIEnv *env, jclass c)
{
	jstring ret;
	char *version = wgVersion();
	if (!version)
		return NULL;
	ret = (*env)->NewStringUTF(env, version);
	free(version);
	return ret;
}
