/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2017-2022 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package main

// #cgo LDFLAGS: -llog
// #include <android/log.h>
// static void callbackAndroid(void *func, int status, const char *msg)
// {
// ((void(*)(int, const char *))func)(status, msg);
// }
import "C"

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

type AndroidLogger struct {
	level C.int
	tag   *C.char
}

var callbackFunc unsafe.Pointer

func cstring(s string) *C.char {
	b, err := unix.BytePtrFromString(s)
	if err != nil {
		b := [1]C.char{}
		return &b[0]
	}
	return (*C.char)(unsafe.Pointer(b))
}

func callbackAndroid(status int, msg string) {
	if uintptr(callbackFunc) == 0 {
		return
	}
	/*
	   logger := &device.Logger{
	       Verbosef: CLogger(0).Printf,
	       Errorf:   CLogger(1).Printf,
	   }
	   logger.Verbosef("newDevice回调成功: %s", msg)
	*/
	C.callbackAndroid(callbackFunc, C.int(status), cstring(msg))
}

func (l AndroidLogger) Printf(format string, args ...interface{}) {
	C.__android_log_write(l.level, l.tag, cstring(fmt.Sprintf(format, args...)))
}

type TunnelHandle struct {
	device *device.Device
	uapi   net.Listener
}

var tunnelHandles map[int32]TunnelHandle
var currServerIP string
var currPublicKey string

func init() {
	tunnelHandles = make(map[int32]TunnelHandle)
	signals := make(chan os.Signal)
	signal.Notify(signals, unix.SIGUSR2)
	go func() {
		buf := make([]byte, os.Getpagesize())
		for {
			select {
			case <-signals:
				n := runtime.Stack(buf, true)
				if n == len(buf) {
					n--
				}
				buf[n] = 0
				C.__android_log_write(C.ANDROID_LOG_ERROR, cstring("WireGuard/GoBackend/Stacktrace"), (*C.char)(unsafe.Pointer(&buf[0])))
			}
		}
	}()
}

//export wgTurnOn
func wgTurnOn(interfaceName string, tunFd int32, settings string, scrambleStr string, callback uintptr) int32 {
	tag := cstring("WireGuard/GoBackend/" + interfaceName)
	logger := &device.Logger{
		Verbosef: AndroidLogger{level: C.ANDROID_LOG_DEBUG, tag: tag}.Printf,
		Errorf:   AndroidLogger{level: C.ANDROID_LOG_ERROR, tag: tag}.Printf,
	}

	tun, name, err := tun.CreateUnmonitoredTUNFromFD(int(tunFd))
	if err != nil {
		unix.Close(int(tunFd))
		logger.Errorf("CreateUnmonitoredTUNFromFD: %v", err)
		return -1
	}

	logger.Verbosef("Attaching to interface %v", name)

	callbackFunc = unsafe.Pointer(callback)
	device := device.NewDevice(tun, conn.NewStdNetBind(), logger, scrambleStr, callbackAndroid)

	err = device.IpcSet(settings)
	if err != nil {
		unix.Close(int(tunFd))
		logger.Errorf("IpcSet: %v", err)
		return -1
	}
	device.DisableSomeRoamingForBrokenMobileSemantics()

	//var uapi net.Listener
	//
	//uapiFile, err := ipc.UAPIOpen(name)
	//if err != nil {
	//	logger.Errorf("UAPIOpen: %v", err)
	//} else {
	//	uapi, err = ipc.UAPIListen(name, uapiFile)
	//	if err != nil {
	//		uapiFile.Close()
	//		logger.Errorf("UAPIListen: %v", err)
	//	} else {
	//		go func() {
	//			for {
	//				conn, err := uapi.Accept()
	//				if err != nil {
	//					return
	//				}
	//				go device.IpcHandle(conn)
	//			}
	//		}()
	//	}
	//}

	err = device.Up()
	if err != nil {
		logger.Errorf("Unable to bring up device: %v", err)
		//uapiFile.Close()
		device.Close()
		return -1
	}
	logger.Verbosef("Device started")

	var i int32
	for i = 0; i < math.MaxInt32; i++ {
		if _, exists := tunnelHandles[i]; !exists {
			break
		}
	}
	if i == math.MaxInt32 {
		logger.Errorf("Unable to find empty handle")
		//uapiFile.Close()
		device.Close()
		return -1
	}
	tunnelHandles[i] = TunnelHandle{device: device, uapi: nil}
	return i
}

//export wgTurnOff
func wgTurnOff(tunnelHandle int32) {
	handle, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	delete(tunnelHandles, tunnelHandle)
	if handle.uapi != nil {
		handle.uapi.Close()
	}
	handle.device.Close()
	goWgRemoveSubIP(currServerIP, currPublicKey)
}

//export wgGetSocketV4
func wgGetSocketV4(tunnelHandle int32) int32 {
	handle, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return -1
	}
	bind, _ := handle.device.Bind().(conn.PeekLookAtSocketFd)
	if bind == nil {
		return -1
	}
	fd, err := bind.PeekLookAtSocketFd4()
	if err != nil {
		return -1
	}
	return int32(fd)
}

//export wgGetSocketV6
func wgGetSocketV6(tunnelHandle int32) int32 {
	handle, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return -1
	}
	bind, _ := handle.device.Bind().(conn.PeekLookAtSocketFd)
	if bind == nil {
		return -1
	}
	fd, err := bind.PeekLookAtSocketFd6()
	if err != nil {
		return -1
	}
	return int32(fd)
}

//export wgGetConfig
func wgGetConfig(tunnelHandle int32) *C.char {
	handle, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return nil
	}
	settings, err := handle.device.IpcGet()
	if err != nil {
		return nil
	}
	return C.CString(settings)
}

//export wgVersion
func wgVersion() *C.char {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return C.CString("unknown")
	}
	for _, dep := range info.Deps {
		if dep.Path == "golang.zx2c4.com/wireguard" {
			parts := strings.Split(dep.Version, "-")
			if len(parts) == 3 && len(parts[2]) == 12 {
				return C.CString(parts[2][:7])
			}
			return C.CString(dep.Version)
		}
	}
	return C.CString("unknown")
}

type subIPResponse struct {
	AllowedIP string `json:"allowed_ip"`
}

//export wgRequestSubIP
func wgRequestSubIP(ip string, publicKey string, uuid string) string {
	AndroidLogger{level: C.ANDROID_LOG_DEBUG, tag: cstring("WireGuard")}.Printf("wgRequestSubIP: %s %s %s", ip, publicKey, uuid)
	return goWgRequestSubIP(ip, publicKey, uuid)
}

func goWgRequestSubIP(ip string, publicKey string, uuid string) string {
	httpClient := &http.Client{
		Timeout: time.Second * 4,
	}
	response, err := httpClient.Post("http://"+ip+":1444"+"/add_peer", "application/json", strings.NewReader(`{"public_key":"`+publicKey+`","uuid":"`+uuid+`"}`))
	if err != nil {
		AndroidLogger{
			level: C.ANDROID_LOG_ERROR,
			tag:   cstring("WireGuard"),
		}.Printf(err.Error())
		return ""
	}
	defer response.Body.Close()
	var resp subIPResponse
	err = json.NewDecoder(response.Body).Decode(&resp)
	if err != nil {
		AndroidLogger{
			level: C.ANDROID_LOG_ERROR,
			tag:   cstring("WireGuard"),
		}.Printf(err.Error())
		return ""
	}
	currServerIP = ip
	currPublicKey = publicKey
	AndroidLogger{level: C.ANDROID_LOG_DEBUG, tag: cstring("WireGuard")}.Printf("wgRequestSubIP: %s", resp.AllowedIP)
	return resp.AllowedIP
}

func goWgRemoveSubIP(ip string, publicKey string) {
	httpClient := &http.Client{
		Timeout: time.Second * 4,
	}
	httpClient.Post("http://"+ip+":1444"+"/remove_peer", "application/json", strings.NewReader(`{"public_key":"`+publicKey+`"}`))
}

func main() {}
