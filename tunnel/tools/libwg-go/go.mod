module golang.zx2c4.com/wireguard/android

go 1.22

toolchain go1.24.0

require (
	golang.org/x/sys v0.13.0
	golang.zx2c4.com/wireguard v0.0.0-20231022001213-2e0774f246fb
)

require (
	github.com/spf13/cast v1.6.0 // indirect
	golang.org/x/crypto v0.14.0 // indirect
	golang.org/x/net v0.17.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

replace golang.zx2c4.com/wireguard v0.0.0-20231022001213-2e0774f246fb => github.com/MogoTechnology/wireguard-go v0.0.17 //go更新时需要更新此版本号
