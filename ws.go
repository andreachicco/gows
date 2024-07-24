package gows

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
)

const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
const (
	NORMAL         = 1000
	PROTOCOL_ERROR = 1002
)

const (
	OP_CONTINUATION     = 0x0
	OP_TEXT             = 0x1
	OP_BINARY           = 0x2
	OP_CLOSE_CONNECTION = 0x8
	OP_PING             = 0x9
	OP_PONG             = 0xA
)

type WebSocket struct {
	conn   net.Conn
	bufio  *bufio.ReadWriter
	status int
}

type Frame struct {
	FIN        bool
	Mask       bool
	OpCode     byte
	PayloadLen uint64
	MaskKey    [4]byte
	Payload    []byte
}

// create new websocket
func New(w http.ResponseWriter) (*WebSocket, error) {
	hj, ok := w.(http.Hijacker)

	if !ok {
		return nil, errors.New("server does not support hijacking")
	}

	conn, bufio, err := hj.Hijack()

	if err != nil {
		return nil, errors.New(err.Error())
	}

	return &WebSocket{
		conn,
		bufio,
		NORMAL,
	}, nil
}

func (ws *WebSocket) write(data []byte) (int, error) {
	n, err := ws.bufio.Write(data)

	if err != nil {
		return 0, err
	}

	err = ws.bufio.Flush()

	if err != nil {
		return 0, err
	}

	return n, nil
}

func (ws *WebSocket) read(bytes int) ([]byte, error) {
	bufferSize := 2048
	data := make([]byte, 0)
	for {
		if len(data) == bytes {
			break
		}
		// Temporary slice to read chunk
		sz := bufferSize
		remaining := bytes - len(data)
		if sz > remaining {
			sz = remaining
		}
		temp := make([]byte, sz)

		n, err := ws.bufio.Read(temp)
		if err != nil && err != io.EOF {
			return data, err
		}

		data = append(data, temp[:n]...)
	}
	return data, nil
}

func getAcceptKey(header http.Header) string {
	h := sha1.New()

	webSocketKey := header.Get("Sec-WebSocket-Key")
	webSocketKey += GUID

	h.Write([]byte(webSocketKey))
	hash := h.Sum(nil)

	accept := base64.StdEncoding.EncodeToString(hash)

	return accept
}

func (ws *WebSocket) HandShake(header http.Header) error {
	accept := getAcceptKey(header)

	response := []string{
		"HTTP/1.1 101 Switching Protocols",
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Accept: " + accept,
		"",
		"",
	}

	_, err := ws.write([]byte(strings.Join(response, "\r\n")))
	return err
}

func (ws *WebSocket) Recv() (*Frame, error) {
	data, err := ws.read(2)

	if err != nil {
		return nil, err
	}

	frame := &Frame{}

	frame.FIN = data[0]&0x80 == 0x80
	frame.OpCode = data[0] & 0xF
	frame.Mask = data[1]&0x80 == 0x80

	if !frame.Mask {
		return nil, errors.New("frames sent by the client must have mask bit set to 1")
	}

	frame.PayloadLen = uint64(data[1] & 0x7F)

	if frame.PayloadLen == 126 {
		data, err = ws.read(2)

		if err != nil {
			return nil, err
		}

		frame.PayloadLen = uint64(binary.BigEndian.Uint16(data))

	} else if frame.PayloadLen == 127 {
		data, err = ws.read(8)

		fmt.Println(data)

		if err != nil {
			return nil, err
		}

		frame.PayloadLen = uint64(binary.BigEndian.Uint64(data))
	}

	if frame.Mask {
		mask, err := ws.read(4)

		if err != nil {
			return nil, err
		}

		frame.MaskKey = [4]byte(mask)
	}

	payload, err := ws.read(int(frame.PayloadLen))

	if err != nil {
		return nil, err
	}

	for b := 0; b < int(frame.PayloadLen); b++ {
		frame.Payload = append(frame.Payload, payload[b]^frame.MaskKey[b%4])
	}

	return frame, nil
}

func (ws *WebSocket) Send(frame *Frame) error {
	data := make([]byte, 2)

	data[0] = frame.OpCode | 0x80

	if frame.FIN {
		data[0] &= 0xFF
	}

	if frame.PayloadLen <= 125 {
		data[1] = byte(frame.PayloadLen)
	} else if frame.PayloadLen > 125 && float64(frame.PayloadLen) < math.Pow(2, 16) {
		data[1] = byte(126)
		length := make([]byte, 2)
		binary.BigEndian.PutUint16(length, uint16(frame.PayloadLen))
		data = append(data, length...)
	} else if float64(frame.PayloadLen) >= math.Pow(2, 16) {
		data[1] = byte(127)
		length := make([]byte, 8)
		binary.BigEndian.PutUint64(length, frame.PayloadLen)
		data = append(data, length...)
	}

	data = append(data, frame.Payload...)

	_, err := ws.write(data)
	return err
}

func (ws *WebSocket) Close() {
	ws.conn.Close()
}
