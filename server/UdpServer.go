package server

import (
	"context"
	"github.com/butnet/udp-nat/protocl"
	"log"
	"net"
	"sync"
	"time"
)

type clientInfo struct {
	lastTime int64
	addr     *net.UDPAddr
}

type CheckUserAndToken func(data protocl.ClientData) bool
type ProcessClientData func(server *UdpServer, data protocl.ClientData, remoteAddr *net.UDPAddr)

type UdpServer struct {
	buffPool          *sync.Pool
	conn              *net.UDPConn
	workCount         int
	messages          chan *protocl.Message
	checkUserAndToken CheckUserAndToken
	clients           map[string]*clientInfo
	lock              *sync.RWMutex
	wait              *sync.WaitGroup
	actions           map[protocl.ActionCode]ProcessClientData
	//客户端信息超时时间，单位：纳秒
	timeout int64
}

// NewUdpServer
func NewUdpServer(workCount int, timeout int64, checkUserAndToken CheckUserAndToken) *UdpServer {
	pool := &sync.Pool{
		New: func() interface{} {
			return &[protocl.MaxUdpDataSize]byte{}
		},
	}
	return &UdpServer{
		workCount:         workCount,
		buffPool:          pool,
		messages:          make(chan *protocl.Message, 100),
		checkUserAndToken: checkUserAndToken,
		clients:           make(map[string]*clientInfo),
		lock:              &sync.RWMutex{},
		wait:              &sync.WaitGroup{},
		timeout:           timeout,
		actions: map[protocl.ActionCode]ProcessClientData{
			protocl.ActionRegedit:           processRegistered,
			protocl.ActionQueryByClientId:   processQueryByClientId,
			protocl.ActionConnectByClientId: processConnectByClientId,
		},
	}
}

func (s *UdpServer) ShutdownAndWait() {
	err := s.conn.Close()
	if err != nil {
		log.Println("关闭监听错误:", err)
	}
	s.wait.Wait()
}

func (s *UdpServer) ListenAndServe(ctx context.Context, addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Println("解析监听地址错误:", err)
		return err
	}

	log.Println("开始监听:", addr)
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Println("监听端口错误:", err)
		return err
	}
	defer udpConn.Close()
	s.conn = udpConn

	for i := 0; i < s.workCount; i++ {
		s.wait.Add(1)
		go func(workId int) {
			defer s.wait.Done()
			s.worker(ctx, workId)
		}(i)
	}

	s.wait.Add(1)
	go func() {
		defer s.wait.Done()
		t := time.NewTimer(time.Second * 3)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.cleanTimeClient()
				t.Reset(time.Second * 3)
			}
		}
	}()

	s.wait.Add(1)
	go func() {
		defer s.wait.Done()
		err = s.serve(ctx)
	}()

	s.wait.Wait()
	return err
}

func (s *UdpServer) serve(ctx context.Context) error {
	log.Println("master: 开始接收消息")
	defer log.Println("master: 接收消息结束")
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		buff := s.buffPool.Get().(*[protocl.MaxUdpDataSize]byte)
		n, remoteAdd, err := s.conn.ReadFromUDP(buff[:])
		if err != nil {
			s.buffPool.Put(buff)
			log.Println("接收:", remoteAdd, "数据包错误:", err)
			return err
		}

		if n == 0 {
			s.buffPool.Put(buff)
			log.Println("接收:", remoteAdd, "接收数据包长度为0")
			continue
		}

		if n+len(protocl.GetClientId()) > protocl.MaxUdpDataSize {
			s.buffPool.Put(buff)
			log.Println("接收:", remoteAdd, "接收数据包超长")
			continue
		}

		s.messages <- &protocl.Message{
			RemoteAdd: remoteAdd,
			Data:      buff[:n:protocl.MaxUdpDataSize],
			Finish:    s.poolItemFinish(buff),
		}
	}
}

func (s *UdpServer) poolItemFinish(buff *[protocl.MaxUdpDataSize]byte) func() {
	return func() {
		s.buffPool.Put(buff)
	}
}

func (s *UdpServer) cleanTimeClient() {
	t := time.Now().UnixNano()
	to := s.timeout
	s.lock.Lock()
	for id, client := range s.clients {
		if t-client.lastTime >= to {
			delete(s.clients, id)
			log.Println("清理过期clientId:", id)
		}
	}
	s.lock.Unlock()
}

func (s *UdpServer) worker(ctx context.Context, workId int) {
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
}

func (s *UdpServer) processMessage(msg *protocl.Message) {
	defer msg.Finish()

	if !protocl.CheckSign(msg.Data) {
		log.Println("签名错误")
		s.sendSignError(msg.RemoteAdd)
		return
	}

	clientData := protocl.ClientData(msg.Data)
	if s.checkUserAndToken != nil && !s.checkUserAndToken(clientData) {
		log.Println("用户名或密码错误")
		s.sendUserOrTokenError(msg.RemoteAdd)
		return
	}

	actionCode := clientData.GetActionCode()
	action, ok := s.actions[actionCode]
	if !ok {
		log.Println("不支持的请求")
		return
	}
	log.Println("处理消息:", clientData.GetClientId(), msg.RemoteAdd, actionCode)
	action(s, clientData, msg.RemoteAdd)
}

func (s *UdpServer) sendSignError(addr *net.UDPAddr) {
	buff := s.buffPool.Get().(*[protocl.MaxUdpDataSize]byte)
	defer s.buffPool.Put(buff)
	data := protocl.ServerData(buff[:])
	data.SetActionCode(protocl.ActionSignError)
	n := data.SignEmpty()
	s.sendData(data[:n], addr)
}

func (s *UdpServer) sendUserOrTokenError(addr *net.UDPAddr) {
	buff := s.buffPool.Get().(*[protocl.MaxUdpDataSize]byte)
	defer s.buffPool.Put(buff)
	data := protocl.ServerData(buff[:])
	data.SetActionCode(protocl.ActionUserOrTokenError)
	n := data.SignEmpty()
	s.sendData(data[:n], addr)
}

func (s *UdpServer) sendPackageError(addr *net.UDPAddr, msg string) {
	buff := s.buffPool.Get().(*[protocl.MaxUdpDataSize]byte)
	defer s.buffPool.Put(buff)
	data := protocl.ServerData(buff[:])
	data.SetActionCode(protocl.ActionPackageError)
	n := data.SignEmpty()
	s.sendData(data[:n], addr)
}

func (s *UdpServer) sendNotFoundClientError(addr *net.UDPAddr, queryClientId string) {
	buff := s.buffPool.Get().(*[protocl.MaxUdpDataSize]byte)
	defer s.buffPool.Put(buff)
	data := protocl.ServerData(buff[:])
	data.SetActionCode(protocl.ActionNotFoundClinetId)
	n := data.SetActionDataAndSign([]byte(queryClientId))
	s.sendData(data[:n], addr)
}

func (s *UdpServer) sendQueryResult(addr *net.UDPAddr, queryClientId string, queryAdd *net.UDPAddr) {
	buff := s.buffPool.Get().(*[protocl.MaxUdpDataSize]byte)
	defer s.buffPool.Put(buff)
	data := protocl.ServerData(buff[:])
	n := protocl.FillQueryClientIdResponse(data, queryClientId, queryAdd)
	s.sendData(data[:n], addr)
}

func (s *UdpServer) sendConnectResult(clientId string, addr *net.UDPAddr, connectClientId string, connectAdd *net.UDPAddr, socketId int) {
	buff := s.buffPool.Get().(*[protocl.MaxUdpDataSize]byte)
	defer s.buffPool.Put(buff)
	data := protocl.ServerData(buff[:])
	//向发起方发送被连接方的地址信息
	n := protocl.FillConnectClientIdResponse(data, connectClientId, connectAdd, socketId)
	s.sendData(data[:n], addr)

	//向被连接方发送发起方的地址信息
	n = protocl.FillConnectClientIdResponse(data, clientId, addr, socketId)
	s.sendData(data[:n], connectAdd)
}

func (s *UdpServer) sendRegisteredSuccess(addr *net.UDPAddr) {
	buff := s.buffPool.Get().(*[protocl.MaxUdpDataSize]byte)
	defer s.buffPool.Put(buff)
	data := protocl.ServerData(buff[:])
	data.SetActionCode(protocl.ActionRegedit)
	n := data.SignEmpty()
	s.sendData(data[:n], addr)
}

func (s *UdpServer) sendData(bytes []byte, addr *net.UDPAddr) {
	n, err := s.conn.WriteToUDP(bytes, addr)
	if err != nil {
		log.Println("发送数据包失败:", err, addr)
	}
	if n != len(bytes) {
		log.Println("发送数据包不完整:", n, len(bytes))
	}
}

func processRegistered(s *UdpServer, data protocl.ClientData, remoteAddr *net.UDPAddr) {
	clientId := data.GetClientId()
	if clientId == "" {
		msg := "查询clientId为空"
		log.Println(msg)
		s.sendPackageError(remoteAddr, msg)
		return
	}

	s.lock.Lock()
	client, ok := s.clients[clientId]
	if !ok {
		s.clients[clientId] = &clientInfo{
			lastTime: time.Now().UnixNano(),
			addr:     remoteAddr,
		}
	} else {
		client.lastTime = time.Now().UnixNano()
		client.addr = remoteAddr
	}
	s.lock.Unlock()

	log.Println("clientId:", clientId, "注册成功")

	s.sendRegisteredSuccess(remoteAddr)
}

//processQueryByClientId 处理查询请求
func processQueryByClientId(s *UdpServer, data protocl.ClientData, remoteAddr *net.UDPAddr) {
	queryClientIdData := data.GetActionData()
	if queryClientIdData == nil {
		msg := "解析数据包失败，clientId is nil"
		log.Println(msg)
		s.sendPackageError(remoteAddr, msg)
		return
	}
	if len(queryClientIdData) == 0 {
		msg := "查询clientId为空"
		log.Println(msg)
		s.sendPackageError(remoteAddr, msg)
		return
	}

	queryClientId := string(queryClientIdData)

	s.lock.RLock()
	client, ok := s.clients[queryClientId]
	s.lock.RUnlock()
	if !ok {
		log.Println("client:", data.GetClientId(), "查询的clientId不存在:", queryClientId)
		s.sendNotFoundClientError(remoteAddr, queryClientId)
		return
	}
	s.sendQueryResult(remoteAddr, queryClientId, client.addr)
}

//processConnectByClientId 处理连接请求
func processConnectByClientId(s *UdpServer, data protocl.ClientData, remoteAddr *net.UDPAddr) {
	connectClientIdData := protocl.ConnectClientIdRequest(data.GetActionData())
	if connectClientIdData == nil {
		msg := "解析数据包失败，clientId is nil"
		log.Println(msg)
		s.sendPackageError(remoteAddr, msg)
		return
	}
	if len(connectClientIdData) == 0 {
		msg := "查询clientId为空"
		log.Println(msg)
		s.sendPackageError(remoteAddr, msg)
		return
	}

	connectClientId := connectClientIdData.GetConnectClientId()

	s.lock.RLock()
	client, ok := s.clients[connectClientId]
	s.lock.RUnlock()
	if !ok {
		log.Println("连接的clientId不存在:", connectClientId)
		s.sendNotFoundClientError(remoteAddr, connectClientId)
		return
	}
	s.sendConnectResult(data.GetClientId(), remoteAddr, connectClientId, client.addr, connectClientIdData.GetSocketId())
}
