package protocl

import (
	"crypto/md5"
	"encoding/binary"
	"errors"
	"log"
	"time"
)

//ClientData userNameLen{1}，userName{userNameLen}，token{md5.Size}, time{8}, clientIdLen{1}, clientId{clientIdLen}, actionCode{1}, actionLen{4}, actionData{actionLen}, sign{16}
type ClientData []byte

func (d ClientData) getUserNameLen() int {
	if len(d) < 1 {
		return 0
	}
	return int(d[0])
}

func (d ClientData) SetUserName(username string) {
	d[0] = byte(len(username))
	copy(d[1:], username)
}

func (d ClientData) GetUserName() string {
	if len(d) < 1 || len(d) < 1+int(d[0]) {
		return ""
	}
	return string(d[1 : 1+d[0]])
}

func (d ClientData) SetToken(password string) {
	t := time.Now().UnixNano()
	token := GenPwdSign(password, t)
	offset := d.getUserNameLen() + 1
	copy(d[offset:], token)
	offset += len(token)
	binary.BigEndian.PutUint64(d[offset:offset+8], uint64(t))
}

func (d ClientData) GetToken() []byte {
	offset := d.getUserNameLen() + 1
	if len(d) < offset+md5.Size {
		return nil
	}
	return d[offset : offset+md5.Size]
}
func (d ClientData) GetTime() int64 {
	offset := d.getUserNameLen() + 1 + md5.Size
	if len(d) < offset+8 {
		return 0
	}
	t := d[offset : offset+8]
	return int64(binary.BigEndian.Uint64(t))
}

func (d ClientData) SetClientId(clientId string) {
	offset := d.getUserNameLen() + 1 + md5.Size + 8
	d[offset] = byte(len(clientId))
	offset++
	copy(d[offset:], clientId)
}

func (d ClientData) GetClientIdLen() int {
	offset := d.getUserNameLen() + 1 + md5.Size + 8
	if len(d) < offset+1 {
		return 0
	}
	return int(d[offset])
}
func (d ClientData) GetClientId() string {
	offset := d.getUserNameLen() + 1 + md5.Size + 8 + 1
	if len(d) < offset+d.GetClientIdLen() {
		return ""
	}
	return string(d[offset : offset+d.GetClientIdLen()])
}

func (d ClientData) GetActionCode() ActionCode {
	offset := d.getUserNameLen() + 1 + md5.Size + 8 + 1 + d.GetClientIdLen()
	if len(d) < offset+1 {
		return 0
	}
	return ActionCode(d[offset])
}

func (d ClientData) SetActionCode(code ActionCode) {
	offset := d.getUserNameLen() + 1 + md5.Size + 8 + 1 + d.GetClientIdLen()
	d[offset] = byte(code)
}

func (d ClientData) SetActionDataLen(size int) {
	offset := d.getUserNameLen() + 1 + md5.Size + 8 + 1 + d.GetClientIdLen() + 1
	binary.BigEndian.PutUint32(d[offset:offset+4], uint32(size))
}

func (d ClientData) GeActionLen() int {
	offset := d.getUserNameLen() + 1 + md5.Size + 8 + 1 + d.GetClientIdLen() + 1
	if len(d) < offset+4 {
		return 0
	}
	return int(binary.BigEndian.Uint32(d[offset : offset+4]))
}

func (d ClientData) SetActionData(data []byte) {
	offset := d.getUserNameLen() + 1 + md5.Size + 8 + 1 + d.GetClientIdLen() + 1
	dataLen := len(data)
	binary.BigEndian.PutUint32(d[offset:offset+4], uint32(dataLen))
	offset += 4
	if data != nil {
		copy(d[offset:], data)
	}
}

func (d ClientData) getActionDataBuff() []byte {
	offset := d.getUserNameLen() + 1 + md5.Size + 8 + 1 + d.GetClientIdLen() + 1 + 4
	return d[offset:]
}

func (d ClientData) GetActionData() []byte {
	offset := d.getUserNameLen() + 1 + md5.Size + 8 + 1 + d.GetClientIdLen() + 1 + 4
	if len(d) < offset+d.GeActionLen() {
		return nil
	}
	return d[offset : offset+d.GeActionLen()]
}

func (d ClientData) Sign() int {
	offset := d.getUserNameLen() + 1 + md5.Size + 8 + 1 + d.GetClientIdLen() + 1 + 4 + d.GeActionLen()
	copy(d[offset:], signSalt)
	sign := md5.Sum(d[:offset+len(signSalt)])
	copy(d[offset:], sign[:])
	return offset + md5.Size
}

func (d ClientData) GetSign() []byte {
	offset := d.getUserNameLen() + 1 + md5.Size + 8 + 1 + d.GetClientIdLen() + 1 + 4 + d.GeActionLen()
	if len(d) < offset+md5.Size {
		return nil
	}
	return d[offset : offset+md5.Size]
}

var UserNameLenError = errors.New("用户名超长")
var ActionDataLenError = errors.New("数据报文越长")

func BuildClientData(username, password string, actionCode ActionCode, actionData []byte) ([]byte, error) {
	user := []byte(username)
	if len(user) > 0xFF {
		log.Println(UserNameLenError)
		return nil, UserNameLenError
	}

	//userNameLen{1}，userName{userNameLen}，token{md5.Size}, time{8}, clientIdLen{1}, clientId{clientIdLen}, actionCode{1}, actionLen{4}, actionData{actionLen}, sign{16}
	size := 1 + len(user) + md5.Size + 8 + 1 + len(clientId) + 1 + 4 + len(actionData) + 16

	if size > MaxUdpDataSize {
		log.Println(ActionDataLenError)
		return nil, ActionDataLenError
	}

	data := make([]byte, size+len(signSalt))
	data[0] = byte(len(user))
	copy(data[1:], user)
	offset := 1 + len(user)

	timeData := [8]byte{}
	binary.BigEndian.PutUint64(timeData[:], uint64(time.Now().UnixNano()))
	copy(data[offset:], genToken(password, timeData))
	offset += md5.Size

	copy(data[offset:], timeData[:])
	offset += 8

	clientIdLen := len(clientId)
	data[offset] = byte(clientIdLen)
	offset += 1

	copy(data[offset:], []byte(clientId))
	offset += clientIdLen

	data[offset] = byte(actionCode)
	offset++

	binary.BigEndian.PutUint32(data[offset:offset+4], uint32(len(actionData)))
	offset += 4

	if actionData != nil {
		copy(data[offset:], actionData)
	}
	offset += len(actionData)

	copy(data[offset:], signSalt)

	sign := md5.Sum(data[:offset+len(signSalt)])
	copy(data[offset:], sign[:])

	return data[:size], nil
}

//func ParseClientMessage(data []byte) (ClientData, bool) {
//	size := len(data)
//	if size < 1 {
//		log.Println("消息长度错误:", size)
//		return nil, false
//	}
//	nameLen := data[0]
//	if nameLen < 0 {
//		log.Println("名字长度错误:", nameLen)
//		return nil, false
//	}
//
//	dataLen := 1 + int(nameLen) + md5.Size + 8 + ClientIdLen + ClientIdLen
//	// userNameLen{1}，userName{userNameLen}，token{16}, time{8}, clientId{ClientIdLen}, queryClientId{ClientIdLen}, sign{16}
//	if dataLen+md5.Size != size {
//		log.Println("数据长度不匹配:", dataLen+md5.Size, size)
//		return nil, false
//	}
//
//	signData := make([]byte, dataLen+len(Salt))
//	copy(signData, data[:dataLen])
//	copy(signData[dataLen:], Salt)
//
//	//log.Println("签名数据:", len(signData), string(signData))
//
//	sign := md5.Sum(signData)
//	if !bytes.Equal(sign[:], data[dataLen:dataLen+md5.Size]) {
//		log.Println("数据校验失败")
//		return nil, false
//	}
//
//	return data, true
//}
