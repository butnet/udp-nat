package protocl

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"
)

//init 初始化默认的clientId
func init() {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	clientIdLen := 16
	clientIdData := make([]byte, 16)
	for i := 0; i < clientIdLen; i++ {
		v := r.Intn(26*2 + 10)
		switch {
		case v < 26:
			clientIdData[i] = byte('a' + v)
		case v < 26*2:
			clientIdData[i] = byte('A' + v - 26)
		default:
			clientIdData[i] = byte('0' + v - 26*2)
		}
	}
	clientId = string(clientIdData[:])
}

//Message 消息
type Message struct {
	//远端地址
	RemoteAdd *net.UDPAddr
	//数据
	Data      []byte
	//消息处理完成后，调用
	Finish    func()
}

//MaxUdpDataSize UDP最大消息长度
const MaxUdpDataSize = 65507

//ActionCode 请求码
type ActionCode byte

const (
	//ActionNotSupport 不支持的命令
	ActionNotSupport ActionCode = iota
	//ActionRegedit 注册
	ActionRegedit
	//ActionSignError 签名错误
	ActionSignError
	//ActionUserOrTokenError 用户名或密码错误
	ActionUserOrTokenError
	//ActionPackageError 解析包错误
	ActionPackageError
	//ActionQueryByClientId 查询ClientId的地址和端口
	ActionQueryByClientId
	//ActionNotFoundClinetId 未找到
	ActionNotFoundClinetId
	//ActionQueryResultByClientId 查询结果
	ActionQueryResultByClientId
	//ActionConnectByClientId 连接请求
	ActionConnectByClientId
)

//默认签名
var signSalt = "butnet"

//SetSignSalt 设置签名串
func SetSignSalt(salt string) {
	if len(salt) > md5.Size {
		panic(fmt.Sprintf("签名字符串不能超过: %d 字节", md5.Size))
	}
	signSalt = salt
}

//获取当前签名串
func GetSignSalt() string {
	return signSalt
}

var clientId string

func SetClientId(id string) {
	if len(id) > 0xFF {
		panic(fmt.Sprintf("clientId 不能超过 %d 字节", 0xFF))
	}
	clientId = id
}

func GetClientId() string {
	return clientId
}

//CheckSign 检查签名是否正在
func CheckSign(data []byte) bool {
	size := len(data)
	if size <= md5.Size {
		return false
	}

	var reqSign [md5.Size]byte
	copy(reqSign[:], data[size-md5.Size:size])

	copy(data[size-md5.Size:], signSalt)
	sign := md5.Sum(data[:size-md5.Size+len(signSalt)])
	return bytes.Equal(reqSign[:], sign[:])
}

func GenPwdSign(pwd string, t int64) []byte {
	pwdData := make([]byte, len(pwd)+8+len(signSalt))
	copy(pwdData, pwd)
	binary.BigEndian.PutUint64(pwdData[len(pwd):], uint64(t))
	copy(pwdData[len(pwd)+8:], signSalt)
	sign := md5.Sum(pwdData)
	return sign[:]
}

func genToken(password string, time [8]byte) []byte {
	pwd := []byte(password)
	data := make([]byte, len(pwd)+8+len(signSalt))
	copy(data, pwd)
	copy(data[len(pwd):], time[:])
	copy(data[len(pwd)+8:], signSalt)
	token := md5.Sum(data)
	return token[:]
}
