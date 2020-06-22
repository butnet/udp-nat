package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/butnet/udp-nat/protocl"
)

type ProcessServerData func(server *UdpClient, data protocl.ServerData)
type ProcessClientData func(server *UdpClient, data protocl.ClientData, remoteAddr *net.UDPAddr)

type UdpClient struct {
	serverAddr            *net.UDPAddr
	username              string
	password              string
	buffPool              *sync.Pool
	conn                  *net.UDPConn
	workCount             int
	messages              chan *protocl.Message
	serverActions         map[protocl.ActionCode]ProcessServerData
	clientActions         map[protocl.ActionCode]ProcessClientData
	clientInfo            map[string]*net.UDPAddr
	wait                  *sync.WaitGroup
	cancelFunc            context.CancelFunc
	testSymmetricNatCount int

	socketId   int
	socketLock *sync.Mutex
}

// New
func New(cancelFunc context.CancelFunc, serverAddr *net.UDPAddr, username, password string, workCount int, testSymmetricNatCount int) *UdpClient {
	pool := &sync.Pool{
		New: func() interface{} {
			return &[protocl.MaxUdpDataSize]byte{}
		},
	}
	return &UdpClient{
		cancelFunc:            cancelFunc,
		serverAddr:            serverAddr,
		username:              username,
		password:              password,
		buffPool:              pool,
		workCount:             workCount,
		messages:              make(chan *protocl.Message, 100),
		testSymmetricNatCount: testSymmetricNatCount,
		serverActions: map[protocl.ActionCode]ProcessServerData{
			protocl.ActionUserOrTokenError:      processUserOrTokenError,
			protocl.ActionPackageError:          processPackageError,
			protocl.ActionNotFoundClinetId:      processNotFoundClientId,
			protocl.ActionQueryResultByClientId: processQueryResultByClientId,
			protocl.ActionConnectByClientId:     processServerConnectByClientId,
			protocl.ActionRegedit:               processRegedit,
		},
		clientActions: map[protocl.ActionCode]ProcessClientData{
			protocl.ActionConnectByClientId: processClientConnectByClientId,
		},
		wait:       &sync.WaitGroup{},
		socketLock: &sync.Mutex{},
	}
}

func (s *UdpClient) ShutdownAndWait() {
	err := s.conn.Close()
	if err != nil {
		log.Println("关闭监听错误:", err)
	}
	s.wait.Wait()
}

func (s *UdpClient) Listen(listenUdpAddr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", listenUdpAddr)
	if err != nil {
		log.Println("解析监听地址错误:", err)
		return err
	}

	log.Println("开始监听:", listenUdpAddr)
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Println("监听端口错误:", err)
		return err
	}
	s.conn = udpConn

	return nil
}

func (s *UdpClient) Regedit(ctx context.Context) {
	s.wait.Add(1)
	go func() {
		log.Println("注册心跳开始")
		defer log.Println("注册心跳结束")
		defer s.wait.Done()
		t := time.NewTimer(time.Nanosecond)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}

			data, err := protocl.BuildClientData(s.username, s.password, protocl.ActionRegedit, nil)
			if err != nil {
				log.Println("构造注册消息错误:", err)
				return
			}
			s.sendData(data, s.serverAddr)
			t.Reset(time.Second * 15)
		}
	}()
}

func (s *UdpClient) Serve(ctx context.Context) {
	s.wait.Add(1)
	go func() {
		defer s.wait.Done()
		log.Println("master: 开始接收消息")
		defer log.Println("master: 接收消息结束")
		for {
			buff := s.buffPool.Get().(*[protocl.MaxUdpDataSize]byte)
			select {
			case <-ctx.Done():
				return
			default:
			}

			n, remoteAdd, err := s.conn.ReadFromUDP(buff[:])
			if err != nil {
				s.buffPool.Put(buff)
				log.Println("接收:", remoteAdd, "数据包错误:", err)
				return
			}

			if n == 0 {
				s.buffPool.Put(buff)
				log.Println("接收:", remoteAdd, "接收数据包长度为0")
				continue
			}

			if n+len(protocl.GetSignSalt()) > protocl.MaxUdpDataSize {
				s.buffPool.Put(buff)
				log.Println("接收:", remoteAdd, "接收数据包超长")
				continue
			}

			log.Println("接收数据:", remoteAdd, n)
			s.messages <- &protocl.Message{
				RemoteAdd: remoteAdd,
				Data:      buff[:n:protocl.MaxUdpDataSize],
				Finish: func() {
					s.buffPool.Put(buff)
				},
			}
		}
	}()
}

func (s *UdpClient) Worker(ctx context.Context) {
	for i := 0; i < s.workCount; i++ {
		s.wait.Add(1)
		go func(workId int) {
			defer s.wait.Done()
			log.Println("worker:", workId, "start")
			defer log.Println("worker:", workId, "finish")
			for {
				select {
				case <-ctx.Done():
					return
				case msg := <-s.messages:
					s.processMessage(msg)
				}
			}
		}(i)
	}
}

func (s *UdpClient) processMessage(msg *protocl.Message) {
	defer msg.Finish()

	if !protocl.CheckSign(msg.Data) {
		log.Println("签名错误")
		return
	}

	if msg.RemoteAdd.Port == s.serverAddr.Port && bytes.Equal(msg.RemoteAdd.IP, s.serverAddr.IP) {
		sd := protocl.ServerData(msg.Data)
		actionCode := sd.GetActionCode()
		action, ok := s.serverActions[actionCode]
		if !ok {
			log.Println("不支持的服务端请求")
			return
		}
		log.Println("处理服务端消息:", msg.RemoteAdd, actionCode)
		action(s, sd)
	} else {
		cd := protocl.ClientData(msg.Data)
		actionCode := cd.GetActionCode()
		action, ok := s.clientActions[actionCode]
		if !ok {
			log.Println("不支持的客户端请求:", actionCode)
			return
		}
		log.Println("处理客户端消息:", msg.RemoteAdd, actionCode)
		action(s, cd, msg.RemoteAdd)
	}
}

func (s *UdpClient) sendData(data []byte, addr *net.UDPAddr) error {
	n, err := s.conn.WriteToUDP(data, addr)
	if err != nil {
		log.Println("发送数据包失败:", err)
		return err
	} else if n != len(data) {
		err = errors.New(fmt.Sprintf("发送列表数据包长度不一致: %d %d", len(data), n))
		log.Println(err)
		return err
	}
	return nil
}

func (s *UdpClient) initClientData(cd protocl.ClientData) {
	cd.SetUserName(s.username)
	cd.SetToken(s.password)
	cd.SetClientId(protocl.GetClientId())
}

func (s *UdpClient) SendQueryRequest(clientId string) {
	buff := s.buffPool.Get().(*[protocl.MaxUdpDataSize]byte)
	defer s.buffPool.Put(buff)
	cd := protocl.ClientData(buff[:])

	s.initClientData(cd)

	n := protocl.FillQueryClientIdRequest(cd, clientId)
	s.sendData(cd[:n], s.serverAddr)
}

func (s *UdpClient) getSocketId() int {
	s.socketLock.Lock()
	s.socketId++
	v := s.socketId
	s.socketLock.Unlock()
	return v
}

func (s *UdpClient) SendConnectRequest(clientId string) {
	buff := s.buffPool.Get().(*[protocl.MaxUdpDataSize]byte)
	defer s.buffPool.Put(buff)
	cd := protocl.ClientData(buff[:])

	s.initClientData(cd)

	n := protocl.FillConnectClientIdRequest(cd, clientId, s.getSocketId())
	s.sendData(cd[:n], s.serverAddr)
}

func (s *UdpClient) SendConnectClientRequest(toClientId string, addr *net.UDPAddr, socketId int) {
	buff := s.buffPool.Get().(*[protocl.MaxUdpDataSize]byte)
	defer s.buffPool.Put(buff)
	cd := protocl.ClientData(buff[:])

	s.initClientData(cd)

	n := protocl.FillConnectClientIdRequest(cd, toClientId, socketId)
	port := addr.Port
	//Symmetric NAT 探测
	for i := 0; i < s.testSymmetricNatCount; i++ {
		addr.Port = port + i
		log.Println("发送连接请求:", toClientId, socketId, addr)
		s.sendData(cd[:n], addr)
	}
}

func processRegedit(s *UdpClient, data protocl.ServerData) {
	log.Println("注册成功")
}

func processUserOrTokenError(s *UdpClient, data protocl.ServerData) {
	log.Println("用户名或密码错误")
	s.cancelFunc()
}

func processPackageError(s *UdpClient, data protocl.ServerData) {
	log.Println("用户名或密码错误")
	s.cancelFunc()
}

func processNotFoundClientId(s *UdpClient, data protocl.ServerData) {
	clientId := string(data.GetActionData())
	log.Println("未找到clientId:", clientId)
}

func processQueryResultByClientId(s *UdpClient, data protocl.ServerData) {
	qs := protocl.QueryClientIdResponse(data.GetActionData())
	ip, port := qs.GetIp(), qs.GetPort()
	addr := &net.UDPAddr{
		IP:   ip,
		Port: port,
	}

	log.Println("找到clientId:", qs.GetClientId(), addr)
}

func processServerConnectByClientId(s *UdpClient, data protocl.ServerData) {
	qs := protocl.ConnectClientIdResponse(data.GetActionData())
	ip, port := qs.GetIp(), qs.GetPort()
	addr := &net.UDPAddr{
		IP:   ip,
		Port: port,
	}

	log.Println("请求链接clientId:", qs.GetClientId(), addr, "socketId:", qs.GetSocketId())
	s.SendConnectClientRequest(qs.GetClientId(), addr, qs.GetSocketId())
}

func processClientConnectByClientId(server *UdpClient, data protocl.ClientData, remoteAddr *net.UDPAddr) {
	req := protocl.ConnectClientIdRequest(data.GetActionData())
	connClientId := req.GetConnectClientId()
	if connClientId != protocl.GetClientId() {
		log.Println("客户端连接请求clientId不匹配:", connClientId, protocl.GetClientId())
		return
	}

	server.socketLock.Lock()
	defer server.socketLock.Unlock()
	log.Println("收到来至的NAT连接请求:", data.GetClientId(), remoteAddr, "socketId:", req.GetSocketId())
	server.clientInfo[connClientId] = remoteAddr
}
