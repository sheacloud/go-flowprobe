package protocols

type Protocol int

const (
	TCP Protocol = iota
	UDP
)

var Protocols = []Protocol{TCP, UDP}
