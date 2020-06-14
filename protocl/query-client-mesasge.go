package protocl

import (
	"encoding/binary"
	"net"
)

//QueryClientIdRequest clientId
type QueryClientIdRequest []byte

//QueryClientIdResponse clientIdLen{1}, clientId{clientIdLen}, ipLen{1}, ip{addrLen}, port{4}
type QueryClientIdResponse []byte

func (qs QueryClientIdResponse) GetClientIdLen() int {
	return int(qs[0])
}

func (qs QueryClientIdResponse) GetClientId() string {
	return string(qs[1 : 1+qs.GetClientIdLen()])
}

func (qs QueryClientIdResponse) GetIpLen() int {
	return int(qs[1+qs.GetClientIdLen()])
}

func (qs QueryClientIdResponse) GetIp() []byte {
	offset := 1 + qs.GetClientIdLen() + 1
	return qs[offset : offset+qs.GetIpLen()]
}

func (qs QueryClientIdResponse) GetPort() int {
	offset := 1 + qs.GetClientIdLen() + 1 + qs.GetIpLen()
	return int(binary.BigEndian.Uint32(qs[offset : offset+4]))
}

func FillQueryClientIdRequest(data ClientData, clientId string) int {
	data.SetActionCode(ActionQueryByClientId)
	data.SetActionData([]byte(clientId))
	return data.Sign()
}

func FillQueryClientIdResponse(data ServerData, clientId string, addr *net.UDPAddr) int {
	ip := addr.IP

	data.SetActionCode(ActionQueryResultByClientId)

	buff := data.GetActionDataBuff()
	offset := 0

	buff[0] = byte(len(clientId))
	offset++

	copy(buff[1:], clientId)
	offset += len(clientId)

	buff[offset] = byte(len(ip))
	offset++

	copy(buff[offset:], ip)
	offset += len(ip)

	binary.BigEndian.PutUint32(buff[offset:offset+4], uint32(addr.Port))
	offset += 4

	data.SetActionDataLen(offset)
	return data.Sign()
}
