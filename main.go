package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/mail"
	"os"
	"strings"
	"time"
)

// SMTPServer SMTP服务器结构体
type SMTPServer struct {
	// 服务器主机地址，端口号，服务器名称等信息。如果不写Host和Port，则监听所有地址的对应端口。
	Host string

	// 监听端口，例如 "25"。通常要指定为25端口。
	Port string

	// 服务器名称，例如 "smtp.example.com"
	ServerName string

	// 认证函数，用于验证用户名和密码
	// 传入用户名和密码，返回是否认证成功
	// 如果不需要认证，可以传入nil
	// 认证函数签名: func(username, password string) bool
	// 这是个模板函数，实际应用中可以根据需要实现不同的认证逻辑；这是设计模式中的模板方法模式。
	AuthFunc func(username, password string) bool
}

// NewSMTPServer 创建新的SMTP服务器实例，保存服务相关的变量
func NewSMTPServer(host, port, name string, authFunc func(username, password string) bool) *SMTPServer {
	return &SMTPServer{
		Host:       host,
		Port:       port,
		ServerName: name,
		AuthFunc:   authFunc,
	}
}

// Start 启动SMTP服务器
func (s *SMTPServer) Start() error {

	// 监听指定的主机和端口,如果Host为空，则监听所有地址。
	listener, err := net.Listen("tcp", ":"+s.Port)
	if err != nil {
		return err
	}
	defer listener.Close()

	fmt.Printf("[ %v ] SMTP服务器在 %s:%s 启动 \n", time.Now().Format("2006-01-02 15:04:05"), s.Host, s.Port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("接受连接失败:", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

// Client 客户端连接结构体
type Client struct {
	conn     net.Conn
	reader   *bufio.Reader
	writer   *bufio.Writer
	server   *SMTPServer
	state    string
	tls      bool
	authed   bool
	mailFrom string
	rcptTo   []string
	data     []string
}

// handleConnection 处理客户端连接
func (s *SMTPServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	fmt.Println("接收到来自", conn.RemoteAddr(), "的连接")

	client := &Client{
		conn:   conn,
		reader: bufio.NewReader(conn),
		writer: bufio.NewWriter(conn),
		server: s,
		state:  "START",
		rcptTo: make([]string, 0),
		data:   make([]string, 0),
	}

	client.greet()
	client.serve()
}

// greet 发送欢迎消息
func (c *Client) greet() {
	c.writeMessage(220, "naive mail ESMTP Service Ready")
}

// writeMessage 写入SMTP响应消息
func (c *Client) writeMessage(code int, message string) error {
	response := fmt.Sprintf("%d %s\r\n", code, message)
	_, err := c.writer.WriteString(response)
	if err != nil {
		return err
	}
	return c.writer.Flush()
}

// writeContinueMessage 写入多行SMTP响应消息
func (c *Client) writeContinueMessage(code int, message string) error {
	//多行消息未结束的格式 %d-%s ，code 和 message 之间有一个短横 "-"
	response := fmt.Sprintf("%d-%s\r\n", code, message)
	_, err := c.writer.WriteString(response)
	if err != nil {
		return err
	}
	return nil
}

// readLine 读取一行数据
func (c *Client) readLine() (string, error) {

	// line, err := c.reader.ReadString('\n')
	// if err != nil {
	// 	return "", err
	// }
	// line = strings.TrimRight(line, "\r\n")
	// return line, nil

	//如果读取的数据非常长，可能会导致阻塞，这里需要设置一个超时机制，防止恶意阻塞。
	//设置30秒的读取超时
	c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer c.conn.SetReadDeadline(time.Time{}) // 清除超时

	//限制读取长度，防止内存耗尽攻击
	// 设置30秒的读取超时并限制读取长度，防止内存耗尽攻击
	const maxAuthLen = 4096 // 限制最大读取字节数
	var buf strings.Builder

	for {
		// 超出长度限制，返回语法错误并终止认证读取
		if buf.Len() > maxAuthLen {
			c.writeMessage(501, "Syntax error in parameters or arguments")
			return "", errors.New("line too long")
		}

		b, err := c.reader.ReadByte()
		if err != nil {
			// 处理超时错误
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				c.writeMessage(504, "Read timeout")
				return "", err
			}
			return "", errors.New("read error: " + err.Error())
		}

		buf.WriteByte(b)
		if b == '\n' {
			break
		}
	}

	return strings.TrimRight(buf.String(), "\r\n"), nil
}

// serve 处理客户端命令
func (c *Client) serve() {
	for {
		line, err := c.readLine()
		if err != nil {
			if c.state == "START" {
				//刚刚连接START状态，就返回EOF,存在恶意行为。
				fmt.Println("[", time.Now().Format("2006-01-02 15:04:05"), "] EOF on START status,connection closed. IP: ", c.conn.RemoteAddr())
				c.conn.Close()
				return
			}
			if err == io.EOF {
				fmt.Println("[", time.Now().Format("2006-01-02 15:04:05"), "] Error is a io.EOF: =>", err, " IP: ", c.conn.RemoteAddr())
				c.conn.Close()
				return
			}
			fmt.Println("[", time.Now().Format("2006-01-02 15:04:05"), "] Error reading message:", err, " IP: ", c.conn.RemoteAddr())
			c.conn.Close()
			return
		}

		fmt.Println("[", time.Now().Format("2006-01-02 15:04:05"), "] Received message: ", line, " from ", c.conn.RemoteAddr())

		parts := strings.SplitN(line, " ", 2)
		command := strings.ToUpper(parts[0])

		if len(parts) < 2 {
			parts = append(parts, "")
		}

		//刚刚连接START状态，未发送 HELO 或者 EHLO
		if c.state == "START" {
			if command != "EHLO" && command != "HELO" {
				fmt.Println("[", time.Now().Format("2006-01-02 15:04:05"), "] On START status,this command is not HELO/EHLO, is ", command, ". IP: ", c.conn.RemoteAddr())
				c.conn.Close()
				return
			}
		}
		if command == "EHLO" || command == "HELO" {
			fmt.Println("[", time.Now().Format("2006-01-02 15:04:05"), "] Check HELO/EHLO params =", parts[1], " IP: ", c.conn.RemoteAddr())
			if parts[1] == "" {
				fmt.Println("[", time.Now().Format("2006-01-02 15:04:05"), "] HELO/EHLO missing domain parameter. IP: ", c.conn.RemoteAddr())
				c.conn.Close()
				return
			}
		}

		switch command {
		case "EHLO":
			c.handleEHLO(parts[1])
		case "HELO":
			c.handleHELO(parts[1])
		case "MAIL":
			c.handleMAIL(parts[1])
		case "RCPT":
			c.handleRCPT(parts[1])
		case "DATA":
			c.handleDATA()
		case "AUTH":
			c.handleAUTH(parts[1])
		case "QUIT":
			c.handleQUIT()
			return
		case "RSET":
			c.handleRSET()
		case "NOOP":
			c.handleNOOP()
		case "STARTTLS":
			c.handleSTARTTLS()
		case "HELP":
			c.handleHELP()
		case "VRFY":
			c.handleVRFY()
		case "EXPN":
			c.handleEXPN()
		default:
			c.writeMessage(502, "Command not implemented")
		}
	}
}

// handleEHLO 处理EHLO命令
func (c *Client) handleEHLO(domain string) {
	c.state = "HELO"
	c.writeContinueMessage(250, fmt.Sprintf("%s greets %s", c.server.ServerName, domain))
	// c.writeContinueMessage(250, "PIPELINING")
	// c.writeContinueMessage(250, "8BITMIME")
	c.writeContinueMessage(250, "SIZE 52428800") // 50MB限制
	c.writeContinueMessage(250, "STARTTLS")
	c.writeContinueMessage(250, "AUTH PLAIN LOGIN")
	c.writeContinueMessage(250, "ENHANCEDSTATUSCODES")
	c.writeMessage(250, "OK")
}

// handleHELO 处理HELO命令
func (c *Client) handleHELO(domain string) {
	c.state = "HELO"
	c.writeMessage(250, fmt.Sprintf("Hello %s, pleased to meet you", domain))
}

// handleMAIL 处理MAIL FROM命令
func (c *Client) handleMAIL(args string) {
	if c.state != "HELO" && c.state != "MAIL" && c.state != "RCPT" {
		c.writeMessage(503, "Bad sequence of commands")
		return
	}

	if !strings.HasPrefix(strings.ToUpper(args), "FROM:") {
		c.writeMessage(501, "Syntax error in parameters or arguments")
		return
	}

	fromPart := strings.TrimSpace(args[5:])

	// 解析邮件地址
	froms := strings.Split(fromPart, " ")
	addr, err := mail.ParseAddress(froms[0])
	if err != nil {
		c.writeMessage(501, "Syntax error in parameters or arguments")
		return
	}

	c.mailFrom = addr.Address
	c.state = "MAIL"
	c.writeMessage(250, "OK")
}

// handleRCPT 处理RCPT TO命令
func (c *Client) handleRCPT(args string) {
	if c.state != "MAIL" && c.state != "RCPT" {
		c.writeMessage(503, "Bad sequence of commands")
		return
	}

	if !strings.HasPrefix(strings.ToUpper(args), "TO:") {
		c.writeMessage(501, "Syntax error in parameters or arguments")
		return
	}

	toPart := strings.TrimSpace(args[3:])

	// 解析邮件地址
	addrs, err := mail.ParseAddressList(toPart)
	if err != nil {
		c.writeMessage(501, "Syntax error in parameters or arguments")
		return
	}

	for _, a := range addrs {
		c.rcptTo = append(c.rcptTo, a.Address)
	}
	c.state = "RCPT"
	c.writeMessage(250, "OK")
}

// handleDATA 处理DATA命令
func (c *Client) handleDATA() {
	if c.state != "RCPT" {
		c.writeMessage(503, "Bad sequence of commands")
		return
	}

	c.writeMessage(354, "End data with <CR><LF>.<CR><LF>")

	var dataLines []string
	for {
		line, err := c.readLine()
		if err != nil {
			return
		}

		if line == "." {
			break
		}

		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}

		dataLines = append(dataLines, line)
	}

	emailContent := strings.Join(dataLines, "\r\n")
	err := c.saveEmail(emailContent)
	if err != nil {
		c.writeMessage(554, "Transaction failed")
		return
	}

	c.state = "DATA"
	c.writeMessage(250, "OK: queued as "+generateMessageID())
}

// saveEmail 保存邮件到.eml文件
func (c *Client) saveEmail(content string) error {
	// 创建emails目录
	if _, err := os.Stat("emails"); os.IsNotExist(err) {
		os.Mkdir("emails", 0755)
	}

	filename := fmt.Sprintf("emails/email_%d.eml", time.Now().UnixNano())
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// 构建完整的邮件头
	receivedHeader := fmt.Sprintf("Received: from %s by %s (SMTP Server); %s\r\n",
		c.conn.RemoteAddr(), c.server.ServerName, time.Now().Format(time.RFC1123Z))
	dateHeader := fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	messageIDHeader := fmt.Sprintf("Message-ID: <%s@%s>\r\n", generateMessageID(), c.server.ServerName)

	emailContent, err := mail.ReadMessage(bytes.NewReader([]byte(content)))
	if err != nil {
		return err
	}
	// 保留原有的Subject头
	subject := emailContent.Header.Get("Subject")
	subjectHeader := fmt.Sprintf("Subject: %s\r\n", subject)

	fullHeaders := receivedHeader + dateHeader + messageIDHeader + subjectHeader + "\r\n"
	fullContent := fullHeaders + content
	_, err = file.WriteString(fullContent)
	return err
}

// handleAUTH 处理AUTH命令
func (c *Client) handleAUTH(args string) {
	if c.state != "HELO" && c.state != "MAIL" && c.state != "RCPT" {
		c.writeMessage(503, "Bad sequence of commands")
		return
	}
	parts := strings.SplitN(args, " ", 2)
	authType := strings.ToUpper(parts[0])

	switch authType {
	case "PLAIN":
		if len(parts) < 2 {
			c.writeMessage(334, "") // 等待客户端发送认证数据
			authData, err := c.readLine()
			if err != nil {
				return
			}
			c.handlePlainAuth(authData)

		} else {
			c.handlePlainAuth(parts[1])
		}
	case "LOGIN":
		c.handleLoginAuth()
	default:
		c.writeMessage(504, "Unrecognized authentication type")
	}
}

// handlePlainAuth 处理PLAIN认证
func (c *Client) handlePlainAuth(authData string) {
	decoded, err := base64.StdEncoding.DecodeString(authData)
	fmt.Println("handlePlainAuth Decoded info:", string(decoded))
	if err != nil {
		c.writeMessage(501, "Syntax error in parameters or arguments")
		return
	}

	parts := strings.Split(string(decoded), "\x00")
	if len(parts) < 3 {
		c.writeMessage(535, "Authentication credentials invalid")
		return
	}

	username := parts[1]
	password := parts[2]

	// 打印解码后的用户名和密码以进行调试
	fmt.Println("Decoded username:", username)
	fmt.Println("Decoded password:", password)

	if c.server.AuthFunc == nil {
		c.writeMessage(535, "5.7.8 Authentication credentials invalid")
		return
	} else {
		//调用认证函数进行认证
		if c.server.AuthFunc(string(username), string(password)) {
			c.authed = true
			c.writeMessage(235, "2.7.0 Authentication successful")
		} else {
			c.writeMessage(535, "5.7.8 Authentication credentials invalid")
		}
	}
}

// handleLoginAuth 处理LOGIN认证
func (c *Client) handleLoginAuth() {
	c.writeMessage(334, "VXNlcm5hbWU6") // Base64 encoded "Username:"

	usernameLine, err := c.readLine()
	if err != nil {
		return
	}

	username, err := base64.StdEncoding.DecodeString(usernameLine)
	fmt.Println("Decoded username:", string(username))
	if err != nil {
		c.writeMessage(501, "Syntax error in parameters or arguments")
		return
	}

	c.writeMessage(334, "UGFzc3dvcmQ6") // Base64 encoded "Password:"

	passwordLine, err := c.readLine()
	if err != nil {
		return
	}

	password, err := base64.StdEncoding.DecodeString(passwordLine)
	fmt.Println("Decoded password:", string(password))
	if err != nil {
		c.writeMessage(501, "Syntax error in parameters or arguments")
		return
	}

	if c.server.AuthFunc == nil {
		c.writeMessage(535, "5.7.8 Authentication credentials invalid")
		return
	} else {
		//调用认证函数进行认证
		if c.server.AuthFunc(string(username), string(password)) {
			c.authed = true
			c.writeMessage(235, "2.7.0 Authentication successful")
		} else {
			c.writeMessage(535, "5.7.8 Authentication credentials invalid")
		}
	}

}

// handleQUIT 处理QUIT命令
func (c *Client) handleQUIT() {
	c.writeMessage(221, "2.0.0 Service closing transmission channel")
}

// handleRSET 处理RSET命令
func (c *Client) handleRSET() {
	c.state = "START"
	c.mailFrom = ""
	c.rcptTo = make([]string, 0)
	c.data = make([]string, 0)
	c.writeMessage(250, "2.0.0 OK")
}

// handleNOOP 处理NOOP命令
func (c *Client) handleNOOP() {
	c.writeMessage(250, "2.0.0 OK")
}

// handleSTARTTLS 处理STARTTLS命令
func (c *Client) handleSTARTTLS() {
	if c.state != "HELO" && c.state != "MAIL" && c.state != "RCPT" {
		c.writeMessage(503, "Bad sequence of commands")
		return
	}

	if c.tls {
		c.writeMessage(503, "Bad sequence of commands")
		return
	}

	c.writeMessage(220, "2.0.0 Ready to start TLS")

	// 这里应该加载真实的证书和私钥
	certFile := "cert/server.crt"
	keyFile := "cert/server.key"
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		certFile = "cert/cert.pem"
		keyFile = "cert/key.pem"
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Println("加载证书失败:", err)
		c.writeMessage(454, "TLS not available")
		return
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   c.server.ServerName,
		MinVersion:   tls.VersionTLS12,
		// GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		// 	// 动态选择证书，例如基于SNI
		// 	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
		// 	if err != nil {
		// 		return nil, err
		// 	}
		// 	return &cert, nil
		// },
	}

	tlsConn := tls.Server(c.conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		log.Println("TLS握手失败:", err)
		tlsConn.Close()
		return
	}

	c.conn = tlsConn
	c.reader = bufio.NewReader(tlsConn)
	c.writer = bufio.NewWriter(tlsConn)
	c.tls = true
	c.state = "START"

}

// handleHELP 处理HELP命令
func (c *Client) handleHELP() {
	helpText := `214-Commands supported:
214-EHLO HELO MAIL RCPT DATA
214-AUTH STARTTLS QUIT RSET
214-NOOP HELP VRFY EXPN
214 End of HELP info`
	lines := strings.Split(helpText, "\n")
	for _, line := range lines {
		c.writeMessage(214, line[4:])
	}
}

// handleVRFY 处理VRFY命令
func (c *Client) handleVRFY() {
	c.writeMessage(252, "Cannot VRFY user, but will accept message and attempt delivery")
}

// handleEXPN 处理EXPN命令
func (c *Client) handleEXPN() {
	c.writeMessage(550, "Access denied to expand")
}

// generateMessageID 生成消息ID
func generateMessageID() string {
	return fmt.Sprintf("%d.%d", time.Now().UnixNano(), os.Getpid())
}

func main() {
	if _, err := os.Stat("cert/cert.pem"); os.IsNotExist(err) {
		generateCertKeys()
	}
	// 身份验证函数
	authFunc := func(username, password string) bool {
	// 示例用户验证，实际应用中应连接数据库
	  	validUsers := map[string]string{
	 		"test@example.com": "password123",
	 		"user@test.com":    "mypassword",
	 		"admin@server.com": "admin123",
	 	}
	 	if validPass, ok := validUsers[username]; ok {
	 		return validPass == password
	 	}
	 	return false
	 }

	server := NewSMTPServer("localhost", "25", "smtp.example.com", authFunc)

	fmt.Println("启动SMTP服务器...")
	if err := server.Start(); err != nil {
		log.Fatal("服务器启动失败:", err)
	}
}

func generateCertKeys() {
	// 生成 RSA 私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// 创建证书模板
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		panic(err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:  []string{"golangle"},
			Country:       []string{"Cn"},
			Province:      []string{"Beijing"},
			Locality:      []string{"Beijing"},
			StreetAddress: []string{"HaidianShangdi"},
			PostalCode:    []string{"100080"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 有效期为一年
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// 生成证书并写入文件
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		panic(err)
	}
	certOut, err := os.Create("cert/cert.pem") // 请确保你有权限写入这个文件或使用其他路径
	if err != nil {
		panic(err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certOut.Close()

	// 保存私钥到文件
	keyOut, err := os.OpenFile("cert/key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	// 注意权限设置，仅限当前用户读写访问
	if err != nil {
		panic(err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	keyOut.Close()

}
