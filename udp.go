package udp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	quic "github.com/lucas-clemente/quic-go"
	"io"
	"math/big"
	"strconv"
)

const StaticKey = "quic_udp_golang_20210817"

type Server struct {
	Handler  func(w Stream, b []byte)
	ProtoKey string
	Mode     int
}

var logger RLogger

type RLogger interface {
	Println(v ...interface{})
}

func Logger(log RLogger) {
	logger = log
}

func print(v ...interface{}) {
	if logger != nil {
		logger.Println(v)
	}
}

type Stream quic.Stream

func New(h func(w Stream, b []byte)) *Server {

	p := &Server{}
	p.Handler = h
	p.ProtoKey = StaticKey
	p.Mode = 0
	return p
}
func (s *Server) SetKey(k string) {
	s.ProtoKey = k
}
func (s *Server) SetMode(m int) {
	s.Mode = m
}

func (s *Server) Run(addr string) {

	listener, err := quic.ListenAddr(addr, generateTLSConfig(s.ProtoKey), nil)
	if err != nil {

		panic(err)
		return
	}
	print("ListenAddr:", addr)

	bg := context.Background()
	cancel, cancelFunc := context.WithCancel(bg)
	defer cancelFunc()
	if s.Mode == 0 {
		for {
			sess, err := listener.Accept(cancel)
			if err != nil {
				print(err)
			} else {

				go s.DealSession(cancel, sess)
			}
		}
	} else {

		for {
			sess, err := listener.Accept(cancel)
			if err != nil {
				print(err)
			} else {

				go s.HeadSession(cancel, sess)
			}
		}
	}

}

func (s *Server) DealSession(ctx context.Context, sess quic.Session) {

	stream, err := sess.AcceptStream(ctx)
	if err != nil {

		print("AcceptStream:", err)
		return
	}
	defer stream.Close()

	var buf [65542]byte
	n, err := stream.Read(buf[0:])
	if err != nil && err != io.EOF {

		print(err)
		return
	}

	result := bytes.NewBuffer(nil)
	result.Write(buf[0:n])

	print(result.String())
	s.Handler(stream, result.Bytes())

}

func (s *Server) HeadSession(ctx context.Context, sess quic.Session) {

	stream, err := sess.AcceptStream(ctx)
	if err != nil {

		print("AcceptStream:", err)
		return
	}
	defer stream.Close()

	lenBytes := make([]byte, 6)

	if _, err := io.ReadFull(stream, lenBytes); err != nil {

		print("Read pack head Error:", err)
		return
	}

	l, err := strconv.Atoi(string(lenBytes))
	if err != nil {

		print("pack length Error:", err)
		return
	}

	print("Server Got len:", l)

	buf := make([]byte, l)
	if _, err := io.ReadFull(stream, buf); err != nil {

		print("Read data Error:", err)
		return
	}

	//print("Server Got: '%s'\n", string(buf))
	s.Handler(stream, buf)

}

// Setup a bare-bones TLS config for the server
func generateTLSConfig(k string) *tls.Config {

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{k},
	}
}

func Request(host, key string, data []byte) ([]byte, int, error) {

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{key},
	}
	session, err := quic.DialAddr(host, tlsConf, nil)
	if err != nil {
		return nil, -1, err
	}

	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		return nil, -1, err
	}

	_, err = stream.Write(data)
	if err != nil {
		return nil, 0, err
	}

	var buf [65542]byte
	n, err := stream.Read(buf[0:])
	if err != nil && err != io.EOF {
		return nil, 1, err
	}

	result := bytes.NewBuffer(nil)
	result.Write(buf[0:n])

	print("Client: Got '%s'\n", result.String())

	return result.Bytes(), 1, nil
}

type Client struct {
	Conn Stream
}

func ClientConn(host, key string) (*Client, error) {

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{key},
	}
	session, err := quic.DialAddr(host, tlsConf, nil)
	if err != nil {

		print(err)
		return nil, err
	}

	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {

		print(err)
		return nil, err
	}

	return &Client{Conn: stream}, nil
}

func (c *Client) Send(data []byte) (int, error) {

	return c.Conn.Write(data)
}

func (c *Client) Recv() ([]byte, error) {

	var buf [65542]byte
	n, err := c.Conn.Read(buf[0:])

	if err != nil && err != io.EOF {

		print(err)
		return nil, err
	}

	result := bytes.NewBuffer(nil)
	result.Write(buf[0:n])

	print("Client: Got:", result.String())

	return result.Bytes(), nil
}

func (c *Client) Read(buf []byte) (int, error) {

	stream := c.Conn
	return io.ReadFull(stream, buf)

}
