package protocl

import (
	"crypto/md5"
	"encoding/binary"
)

//ServerData actionCode{1}, actionDataLen{4}, actionData{addrLen}, sign{16}
type ServerData []byte

func (d ServerData) SetActionCode(code ActionCode) {
	d[0] = byte(code)
}

func (d ServerData) SetActionDataAndSign(data []byte) int {
	size := len(data)
	binary.BigEndian.PutUint32(d[1:5], uint32(size))
	if data != nil {
		copy(d[5:], data)
	}

	copy(d[5+size:], signSalt)
	sign := md5.Sum(d[:5+size+len(signSalt)])
	copy(d[5+size:], sign[:])

	return 1 + 4 + size + md5.Size
}

func (d ServerData) GetActionDataBuff() []byte {
	return d[5:]
}

func (d ServerData) SetActionDataLen(size int) {
	binary.BigEndian.PutUint32(d[1:5], uint32(size))
}

func (d ServerData) SetActionData(data []byte) int {
	size := len(data)
	binary.BigEndian.PutUint32(d[1:5], uint32(size))
	if data != nil {
		copy(d[5:], data)
	}

	return 1 + 4 + size
}

func (d ServerData) AppendActionData(data []byte) int {
	size := len(data)
	oldSize := int(binary.BigEndian.Uint32(d[5 : 5+4]))
	binary.BigEndian.PutUint32(d[1:5], uint32(size+oldSize))
	if data != nil {
		copy(d[5+oldSize:], data)
	}

	return 1 + 4 + oldSize + size
}

func (d ServerData) SignEmpty() int {
	d[5] = 0
	d[6] = 0
	d[7] = 0
	d[8] = 0
	oldSize := 0
	dataSize := 1 + 4 + oldSize
	copy(d[dataSize:], signSalt)
	sign := md5.Sum(d[:dataSize+len(signSalt)])
	copy(d[dataSize:], sign[:])
	return dataSize + md5.Size
}

func (d ServerData) Sign() int {
	oldSize := int(binary.BigEndian.Uint32(d[1 : 1+4]))
	dataSize := 1 + 4 + oldSize
	copy(d[dataSize:], signSalt)
	sign := md5.Sum(d[:dataSize+len(signSalt)])
	copy(d[dataSize:], sign[:])
	return dataSize + md5.Size
}

func (d ServerData) GetActionCode() ActionCode {
	if len(d) < 1 {
		return 0
	}
	return ActionCode(d[0])
}

func (d ServerData) GetActionDataLen() int {
	offset := 1
	if len(d) < offset+4 {
		return 0
	}
	return int(binary.BigEndian.Uint32(d[offset : offset+4]))
}

func (d ServerData) GetActionData() []byte {
	offset := 1 + 4
	dataLen := d.GetActionDataLen()
	if len(d) < offset+dataLen {
		return nil
	}
	return d[offset : offset+dataLen]
}

func BuildServerData(actionCode ActionCode, actionData []byte) []byte {
	actionDataLen := len(actionData)
	dataSize := 1 + 4 + actionDataLen
	buff := make([]byte, dataSize+md5.Size+len(signSalt))

	offset := 0
	buff[offset] = byte(actionCode)
	offset++

	binary.BigEndian.PutUint32(buff[offset:offset+4], uint32(actionDataLen))
	offset += 4

	if actionData != nil {
		copy(buff[offset:], actionData)
	}
	offset += actionDataLen

	copy(buff[offset:], signSalt)
	sign := md5.Sum(buff[:dataSize+len(signSalt)])
	copy(buff[offset:], sign[:])

	return buff[:dataSize+md5.Size]
}

//func ParseServerMessage(data []byte) (ServerData, bool) {
//	size := len(data)
//	if size < 1+ClientIdLen+1 {
//		log.Println("消息长度错误:", size)
//		return nil, false
//	}
//	result := ResultCode(data[0])
//	if result != Success {
//		log.Println("响应错误码:", result)
//		return nil, false
//	}
//
//	addrLen := int(data[1+ClientIdLen])
//	if addrLen <= 0 {
//		log.Println("用户列表IP地址长度错误:", addrLen)
//		return nil, false
//	}
//
//	dataLen := 1 + ClientIdLen + 1 + addrLen + 4
//	// result{1}, clientId{ClientIdLen}, addrLen{1}, addr{addrLen}, port{4}, sign{16}
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
