package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"github.com/butnet/udp-nat/protocl"
	"github.com/butnet/udp-nat/server"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var port int
var workCount int
var timeout int64
var salt string
var userConfigPath string

func init() {
	flag.IntVar(&port, "port", 8520, "监听端口")
	flag.IntVar(&workCount, "workCount", 10, "工作协程数")
	flag.Int64Var(&timeout, "timeout", 30, "客户端超时时间，单位：秒")
	flag.StringVar(&salt, "salt", "", "签名字符串")
	flag.StringVar(&userConfigPath, "userConfig", "user.conf", "用户名密码配置")
}

func main() {
	flag.Parse()
	if salt != "" {
		protocl.SetSignSalt(salt)
	}

	users, err := server.ParseUserList(userConfigPath)
	if err != nil {
		log.Println("读取用户配置文件失败:", err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	server := server.NewUdpServer(workCount, timeout * int64(time.Second), genCheckUserAndToken(users))

	go func() {
		defer cancel()
		err := server.ListenAndServe(ctx, fmt.Sprintf(":%d", port))
		if err != nil {
			log.Println("服务结束:", err)
		}
	}()

	quit := make(chan os.Signal)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-quit:
		log.Println("关闭服务 ...")
		cancel()
		server.ShutdownAndWait()
		log.Println("服务结束")
	case <-ctx.Done():
		log.Println("服务结束")
	}
}

func genCheckUserAndToken(users map[string]string) server.CheckUserAndToken {
	return func(data protocl.ClientData) bool {
		pwd, ok := users[data.GetUserName()]
		if !ok {
			return false
		}
		sign := protocl.GenPwdSign(pwd, data.GetTime())
		return bytes.Equal(sign[:], data.GetToken())
	}
}
