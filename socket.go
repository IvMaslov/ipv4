package ipv4

import (
	"net"

	"github.com/IvMaslov/ethernet"
	"github.com/IvMaslov/netutils"
)

var broadcastIP = IPAddr{255, 255, 255, 255}

type IpSocket struct {
	ethSock     *ethernet.EtherSocket
	ipInfo      *netutils.InterfaceInfo
	gatewayInfo *netutils.InterfaceInfo

	dstIP IPAddr
}

func NewIpSocket(es *ethernet.EtherSocket) (*IpSocket, error) {
	ipSock := &IpSocket{
		ethSock: es,
	}

	ipInfo, err := netutils.GetInterfaceInfo(es.Name())
	if err != nil {
		return nil, err
	}

	gatewayInfo, err := netutils.GetDefaultGatewayInfo(es.Name())
	if err != nil {
		return nil, err
	}

	ipSock.ipInfo = &ipInfo
	ipSock.gatewayInfo = &gatewayInfo
	ipSock.dstIP = broadcastIP // by default write to all

	return ipSock, nil
}

// Name returns of interface
func (is *IpSocket) Name() string {
	return is.ethSock.Name()
}

// GetIp returns ip address of interface
func (is *IpSocket) GetIp() net.IP {
	return is.ipInfo.IP
}

// GetGatewayIp returns ip address of interface's gateway
func (is *IpSocket) GetGatewayIp() net.IP {
	return is.gatewayInfo.IP
}

// GetDstIp returns destination ip
func (is *IpSocket) GetDstIp() IPAddr {
	return is.dstIP
}

// GetMac returns mac address of underlying device
func (is *IpSocket) GetMac() net.HardwareAddr {
	return is.ipInfo.HardAddr
}

// GetGatewayMac returns mac address of underlying device's gateway
func (is *IpSocket) GetGatewayMac() net.HardwareAddr {
	return is.gatewayInfo.HardAddr
}

// Read returns data of IP packet
func (is *IpSocket) Read() ([]byte, error) {
	p, err := is.ReadPacket()
	if err != nil {
		return nil, err
	}

	return p.Data, nil
}

// ReadPacket returns full ip packet with data
func (is *IpSocket) ReadPacket() (*Packet, error) {
	for {
		frame, err := is.ethSock.ReadFrame()
		if err != nil {
			return nil, err
		}

		if frame.EtherType != ethernet.EtherTypeIPv4 {
			continue
		}

		p := &Packet{}

		p.Unmarshal(frame.Payload)

		return p, nil
	}
}

// Connect sets up destination ip address, by default is broadcast
func (is *IpSocket) Connect(to IPAddr) {
	is.dstIP = to
}

// Write sends data to destination ip
func (is *IpSocket) Write(data []byte) error {
	p := New(IPAddr(is.ipInfo.IP), is.dstIP, data)

	return is.WritePacket(p)
}

// WriteTo sends data to certain ip address
func (is *IpSocket) WriteTo(to IPAddr, data []byte) error {
	p := New(IPAddr(is.ipInfo.IP), to, data)

	return is.WritePacket(p)
}

// WritePacket sends ready packet
func (is *IpSocket) WritePacket(p *Packet) error {
	data := p.Marshal()

	return is.ethSock.Write(data)
}
