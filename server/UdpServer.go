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

//CheckUserAndToken 校验用户
type CheckUserAndToken func(data protocl.ClientData) bool
//ProcessClientData 处理客户端消息
type ProcessClientData func(server *UdpServer, data protocl.ClientData, remoteAddr *net.UDPAddr)

//UdpServer UdpNat服务
type UdpServer struct {
	//消息缓冲区对象池
	buffPool          *sync.Pool
	//当前UDP监听
	conn              *net.UDPConn
	//处理消息的协程个数
	workCount         int
	//待处理的消息管道
	messages          chan *protocl.Message
	//用户校验
	checkUserAndToken CheckUserAndToken
	//当前注册的客户端信息
	clients           map[string]*clientInfo
	//对clients的读写锁
	lock              *sync.RWMutex
	//当前服务协和
	wait              *sync.WaitGroup
	//当前服务支持的消息
	actions           map[protocl.ActionCode]ProcessClientData
	//客户端信息超时时间，单位：纳秒
	timeout int64
}

// NewUdpServer 创建服务
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

//ShutdownAndWait 关闭服务并待所有协程处理结束
func (s *UdpServer) ShutdownAndWait() {
	err := s.conn.Close()
	if err != nil {
		log.Println("关闭监听错误:", err)
	}
	s.wait.Wait()
}

//ListenAndServe 监听端口并开始服务
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

	//清理过期的clientId
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

//serve 接收UDP消息，发送给管道
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

//poolItemFinish 消息处理结束后，将消息缓冲区放回对象池
func (s *UdpServer) poolItemFinish(buff *[protocl.MaxUdpDataSize]byte) func() {
	return func() {
		s.buffPool.Put(buff)
	}
}

//cleanTimeClient 清理过期的clientId
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

//worker 负责接收管道消息
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
	//检查消息签名
	if !protocl.CheckSign(msg.Data) {
		log.Println("签名错误")
		s.sendSignError(msg.RemoteAdd)
		return
	}

	clientData := protocl.ClientData(msg.Data)
	//校验用户是否允许
	if s.checkUserAndToken != nil && !s.checkUserAndToken(clientData) {
		log.Println("用户名或密码错误")
		s.sendUserOrTokenError(msg.RemoteAdd)
		return
	}

	//请求命令
	actionCode := clientData.GetActionCode()
	action, ok := s.actions[actionCode]
	if !ok {
		log.Println("不支持的请求")
		return
	}
	log.Println("处理消息:", clientData.GetClientId(), msg.RemoteAdd, actionCode)
	action(s, clientData, msg.RemoteAdd)
}

//sendSignError 发送签名错误消息
func (s *UdpServer) sendSignError(addr *net.UDPAddr) {
	buff := s.buffPool.Get().(*[protocl.MaxUdpDataSize]byte)
	defer s.buffPool.Put(buff)
	data := protocl.ServerData(buff[:])
	data.SetActionCode(protocl.ActionSignError)
	n := data.SignEmpty()
	s.sendData(data[:n], addr)
}

//sendUserOrTokenError 发送用户名或密码错误消息
func (s *UdpServer) sendUserOrTokenError(addr *net.UDPAddr) {
	buff := s.buffPool.Get().(*[protocl.MaxUdpDataSize]byte)
	defer s.buffPool.Put(buff)
	data := protocl.ServerData(buff[:])
	data.SetActionCode(protocl.ActionUserOrTokenError)
	n := data.SignEmpty()
	s.sendData(data[:n], addr)
}

//sendPackageError 发送数据包格式错误
func (s *UdpServer) sendPackageError(addr *net.UDPAddr, msg string) {
	buff := s.buffPool.Get().(*[protocl.MaxUdpDataSize]byte)
	defer s.buffPool.Put(buff)
	data := protocl.ServerData(buff[:])
	data.SetActionCode(protocl.ActionPackageError)
	n := data.SignEmpty()
	s.sendData(data[:n], addr)
}

//sendNotFoundClientError 发送ClientId未找到
func (s *UdpServer) sendNotFoundClientError(addr *net.UDPAddr, queryClientId string) {
	buff := s.buffPool.Get().(*[protocl.MaxUdpDataSize]byte)
	defer s.buffPool.Put(buff)
	data := protocl.ServerData(buff[:])
	data.SetActionCode(protocl.ActionNotFoundClinetId)
	n := data.SetActionDataAndSign([]byte(queryClientId))
	s.sendData(data[:n], addr)
}

//sendQueryResult 发送查询结果
func (s *UdpServer) sendQueryResult(addr *net.UDPAddr, queryClientId string, queryAdd *net.UDPAddr) {
	buff := s.buffPool.Get().(*[protocl.MaxUdpDataSize]byte)
	defer s.buffPool.Put(buff)
	data := protocl.ServerData(buff[:])
	n := protocl.FillQueryClientIdResponse(data, queryClientId, queryAdd)
	s.sendData(data[:n], addr)
}

//sendConnectResult 发送连接结果
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

//sendRegisteredSuccess 发送注册成功
func (s *UdpServer) sendRegisteredSuccess(addr *net.UDPAddr) {
	buff := s.buffPool.Get().(*[protocl.MaxUdpDataSize]byte)
	defer s.buffPool.Put(buff)
	data := protocl.ServerData(buff[:])
	data.SetActionCode(protocl.ActionRegedit)
	n := data.SignEmpty()
	s.sendData(data[:n], addr)
}

//sendData 发送UDP底层数据报文
func (s *UdpServer) sendData(bytes []byte, addr *net.UDPAddr) {
	n, err := s.conn.WriteToUDP(bytes, addr)
	if err != nil {
		log.Println("发送数据包失败:", err, addr)
	}
	if n != len(bytes) {
		log.Println("发送数据包不完整:", n, len(bytes))
	}
}

//processRegistered 处理注册请求
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
