package protocl

import (
	"encoding/binary"
	"net"
)

//ConnectClientIdRequest clientIdLen{1}, clientId{clientIdLen}, socketId{4}
type ConnectClientIdRequest []byte

func (r ConnectClientIdRequest) GetConnectClientIdLen() int {
	return int(r[0])
}

func (r ConnectClientIdRequest) GetConnectClientId() string {
	return string(r[1 : 1+r.GetConnectClientIdLen()])
}

func (r ConnectClientIdRequest) GetSocketId() int {
	idLen := 1 + r.GetConnectClientIdLen()
	return int(binary.BigEndian.Uint32(r[idLen : idLen+4]))
}

//ConnectClientIdResponse clientIdLen{1}, clientId{clientIdLen}, socketId{4}, ipLen{1}, ip{addrLen}, port{4}
type ConnectClientIdResponse []byte

func (qs ConnectClientIdResponse) GetClientIdLen() int {
	return int(qs[0])
}

func (qs ConnectClientIdResponse) GetClientId() string {
	return string(qs[1 : 1+qs.GetClientIdLen()])
}

func (qs ConnectClientIdResponse) GetSocketId() int {
	offset := 1 + qs.GetClientIdLen()
	return int(binary.BigEndian.Uint32(qs[offset : offset+4]))
}

func (qs ConnectClientIdResponse) GetIpLen() int {
	return int(qs[1+qs.GetClientIdLen()+4])
}

func (qs ConnectClientIdResponse) GetIp() []byte {
	offset := 1 + qs.GetClientIdLen() + 4 + 1
	return qs[offset : offset+qs.GetIpLen()]
}

func (qs ConnectClientIdResponse) GetPort() int {
	offset := 1 + qs.GetClientIdLen() + 4 + 1 + qs.GetIpLen()
	return int(binary.BigEndian.Uint32(qs[offset : offset+4]))
}

func FillConnectClientIdRequest(data ClientData, clientId string, socketId int) int {
	data.SetActionCode(ActionConnectByClientId)
	buff := data.getActionDataBuff()
	buff[0] = byte(len(clientId))
	copy(buff[1:], clientId)
	offset := 1 + len(clientId)
	binary.BigEndian.PutUint32(buff[offset:offset+4], uint32(socketId))
	offset += 4
	data.SetActionDataLen(offset)
	return data.Sign()
}

func FillConnectClientIdResponse(data ServerData, clientId string, addr *net.UDPAddr, socketId int) int {
	ip := addr.IP

	data.SetActionCode(ActionConnectByClientId)

	buff := data.GetActionDataBuff()
	offset := 0

	buff[0] = byte(len(clientId))
	offset++

	copy(buff[1:], []byte(clientId))
	offset += len(clientId)

	binary.BigEndian.PutUint32(buff[offset:offset+4], uint32(socketId))
	offset += 4

	buff[offset] = byte(len(ip))
	offset++

	copy(buff[offset:], ip)
	offset += len(ip)

	binary.BigEndian.PutUint32(buff[offset:offset+4], uint32(addr.Port))
	offset += 4

	data.SetActionDataLen(offset)
	return data.Sign()
}
