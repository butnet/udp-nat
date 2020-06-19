package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/butnet/udp-nat/client"
	"github.com/butnet/udp-nat/protocl"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

var host string
var port int
var udpPort int
var proxyPort int
var tcpPort int
var workCount int
var testSymmetricNat int
var username string
var password string
var clientId string
var toClientId string
var salt string

func init() {
	flag.StringVar(&host, "host", "", "服务器地址")
	flag.IntVar(&port, "port", 8520, "服务器端口")
	flag.IntVar(&udpPort, "uport", 9630, "UDP本地端口")
	flag.IntVar(&proxyPort, "pport", 0, "代理本地TCP端口")
	flag.IntVar(&tcpPort, "tport", 0, "本地TCP端口")
	flag.IntVar(&workCount, "workCount", 10, "处理消息的协程数")
	flag.IntVar(&testSymmetricNat, "testSymmetricNat", 100, "探测 Symmetric Nat 类型次数")
	flag.StringVar(&clientId, "clientId", "", "ClientId")
	flag.StringVar(&toClientId, "toClientId", "", "连接的目标clientId")
	flag.StringVar(&username, "username", "", "用户名")
	flag.StringVar(&password, "password", "", "密码")
	flag.StringVar(&salt, "salt", "", "签名字符串")
}

func main() {
	flag.Parse()
	if salt != "" {
		protocl.SetSignSalt(salt)
	}
	if clientId != "" {
		protocl.SetClientId(clientId)
	}
	//if (proxyPort > 0 && tcpPort > 0) || (proxyPort == 0 && tcpPort == 0) {
	//	log.Println("pport 和 tcport 必须且只能指定一个")
	//	return
	//}

	raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		log.Println("服务器地址错误:", err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	udpClient := client.New(cancel, raddr, username, password, workCount, testSymmetricNat)
	err = udpClient.Listen(fmt.Sprintf(":%d", udpPort))
	if err != nil {
		log.Println("监听UDP端口:", udpPort, err)
	}
	defer udpClient.ShutdownAndWait()

	//注册心跳
	udpClient.Regedit(ctx)
	//监听服务
	udpClient.Serve(ctx)
	//处理消息
	udpClient.Worker(ctx)

	if proxyPort > 0 && tcpPort == 0 {
		//代理服务端模式
	} else if proxyPort == 0 && tcpPort > 0 {
		//代理客户端模式
	}

	if toClientId != "" {
		udpClient.SendConnectRequest(toClientId)
	}

	quit := make(chan os.Signal)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-quit:
		log.Println("关闭服务 ...")
		cancel()
		udpClient.ShutdownAndWait()
		log.Println("服务结束")
	case <-ctx.Done():
		log.Println("服务结束")
	}
}
