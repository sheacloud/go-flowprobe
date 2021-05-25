package protocols

type TCPState string

const (
	TCPStateEstablished = "ESTABLISHED"
	TCPStateFinWait1    = "FIN_WAIT_1"
	TCPStateCloseWait   = "CLOSE_WAIT"
	TCPStateFinWait2    = "FIN_WAIT_2"
	TCPStateLastAck     = "LAST_ACK"
	TCPStateTimeWait    = "TIME_WAIT"
	TCPStateClosed      = "CLOSED"
	TCPStateResetAcked  = "RESET_ACK"
)
