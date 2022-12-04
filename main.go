package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/ssh"
	terminal "golang.org/x/term"
)

type CliArgument struct {
	Addr    string
	Debug   bool
	LogDir  string
	PrivKey string
}

var cliArgument CliArgument
var logger *zap.Logger

func init() {
	pflag.StringVarP(&cliArgument.Addr, "address", "a", "0.0.0.0:2222", "Bind address")
	pflag.BoolVarP(&cliArgument.Debug, "debug", "d", false, "toggle debug mode")
	pflag.StringVarP(&cliArgument.LogDir, "log", "l", "./", "Log output dir.")
	pflag.StringVarP(&cliArgument.PrivKey, "privatekey", "p", "priv.pem", "SSH private key")
	pflag.Usage = func() {
		fmt.Printf("|---------------------------------------------------------------|\n")
		fmt.Printf("|                                                               |\n")
		fmt.Printf("|             SSH Honeypot written in Go                        |\n")
		fmt.Printf("|                                                               |\n")
		fmt.Printf("| This SSH daemon will accept any username/password/key.        |\n")
		fmt.Printf("| It only allows 'session' channels (not port forwards or SFTP).|\n")
		fmt.Printf("| It will present a fake shell and record any commands that     |\n")
		fmt.Printf("| people attempt to run, along with the date and their IP.      |\n")
		fmt.Printf("|                                                               |\n")
		fmt.Printf("| Usage:                                                        |\n")
		fmt.Printf("|   %s [options]                                                |\n", os.Args[0])
		fmt.Printf("|                                                               |\n")
		fmt.Printf("|---------------------------------------------------------------|\n")
		pflag.PrintDefaults()
		os.Exit(0)
	}
}

func setupLogger() error {
	file, err := os.OpenFile(path.Join(cliArgument.LogDir, "sshhighpot.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}

	if cliArgument.Debug {
		enc := zap.NewDevelopmentEncoderConfig()
		enc.EncodeTime = func(t time.Time, pae zapcore.PrimitiveArrayEncoder) {
			pae.AppendString(t.Format(time.RFC3339))
		}

		logger = zap.New(
			zapcore.NewTee(
				zapcore.NewCore(zapcore.NewConsoleEncoder(enc), zapcore.Lock(os.Stderr), zap.InfoLevel),
				zapcore.NewCore(zapcore.NewJSONEncoder(enc), zapcore.Lock(file), zap.InfoLevel),
			),
			zap.AddCaller(),
			zap.AddStacktrace(zap.ErrorLevel),
		)
	} else {
		enc := zap.NewProductionEncoderConfig()
		enc.EncodeTime = func(t time.Time, pae zapcore.PrimitiveArrayEncoder) {
			pae.AppendString(t.Format(time.RFC3339))
		}

		logger = zap.New(
			zapcore.NewTee(
				zapcore.NewCore(zapcore.NewConsoleEncoder(enc), zapcore.Lock(os.Stderr), zap.InfoLevel),
				zapcore.NewCore(zapcore.NewJSONEncoder(enc), zapcore.Lock(file), zap.InfoLevel),
			),
			zap.AddCaller(),
			zap.AddStacktrace(zap.ErrorLevel),
		)
	}

	return nil
}

// loadPrivKey load private key from file, if file not exists,
// generate one.
func loadPrivKey(privKey string) ssh.Signer {
	var privatekey []byte
	if file, err := os.OpenFile(cliArgument.PrivKey, os.O_RDONLY, 0o600); err != nil {
		if os.IsNotExist(err) {
			logger.Info("Private key not exists, generate now", zap.String("privatekey", cliArgument.PrivKey))
			privatekey = generateHostKey(1024)
			if file, err := os.OpenFile(cliArgument.PrivKey, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600); err != nil {
				logger.Fatal("open private key for write failed", zap.String("filepath", cliArgument.PrivKey), zap.Error(err))
			} else {
				defer file.Close()
				file.Write(privatekey)
			}
		} else {
			logger.Fatal("open private key for read failed", zap.String("filepath", cliArgument.PrivKey), zap.Error(err))
		}
	} else {
		var err error
		privatekey, err = io.ReadAll(file)
		if err != nil {
			logger.Fatal("read private key failed", zap.String("filepath", cliArgument.PrivKey), zap.Error(err))
		}
	}

	logger.Info("Private key loaded from file", zap.String("privatekey", cliArgument.PrivKey))
	hostKey, err := ssh.ParsePrivateKey(privatekey)
	if err != nil {
		logger.Fatal("Error: Failed to parse host key", zap.Error(err))
	}

	return hostKey
}

func main() {
	pflag.Parse()
	setupLogger()

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		PasswordCallback:            passwordCallback,
		PublicKeyCallback:           publicKeyCallback,
		KeyboardInteractiveCallback: keyboardInteractiveCallback,
	}

	// Setup a host key to use
	config.AddHostKey(loadPrivKey(cliArgument.PrivKey))

	// Now that we've configured the server, we can start listening
	listener, err := net.Listen("tcp", cliArgument.Addr)
	if err != nil {
		logger.Fatal("Error: Failed to bind address", zap.String("address", cliArgument.Addr), zap.Error(err))
	}

	logger.Sugar().Infof("Listening on %s", cliArgument.Addr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			// A ServerConn multiplexes several channels, which must
			// themselves be Accepted.
			networkConnection, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					logger.Sugar().Infof("Error: Failed to accept an incoming connection from %s (%s)", listener.Addr().String(), err)
					continue
				}
			}

			// Launch a new goroutine (lite-thread) to handle the connection
			// freeing us up to accept more.
			go handleNetworkConnection(networkConnection, config)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c

	logger.Info("Received a ctrl+c - shutting down...")
	cancel()
	if listener != nil {
		listener.Close()
	}
}

func passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	// Accept any username/password
	logger.Sugar().Infof("Accepted user authentication (%s/%s) from %s", conn.User(), string(password), conn.RemoteAddr().String())
	return &ssh.Permissions{}, nil
}

func publicKeyCallback(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	// Accept any private key
	logger.Sugar().Infof("Accepted key authentication for user %s from %s", conn.User(), conn.RemoteAddr().String())
	return &ssh.Permissions{}, nil
}

func keyboardInteractiveCallback(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	// Accept any private key
	logger.Sugar().Infof("Accepted keyboard interactive authentication for user %s from %s", conn.User(), conn.RemoteAddr().String())
	return &ssh.Permissions{}, nil
}

func handleNetworkConnection(networkConnection net.Conn, config *ssh.ServerConfig) {
	serverConnection, newChan, _, err := ssh.NewServerConn(networkConnection, config)
	if err != nil {
		logger.Sugar().Infof("Error: SSH handshake failed (%s)", err)
		networkConnection.Close()
		return
	}

	for {
		// Accept reads from the connection, demultiplexes packets
		// to their corresponding channels and returns when a new
		// channel request is seen. Some goroutine must always be
		// calling Accept; otherwise no messages will be forwarded
		// to the channels.
		channelRequest := <-newChan
		if channelRequest == nil {
			logger.Sugar().Infof("Connection closed: %s", networkConnection.RemoteAddr())
			return
		}

		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.

		switch channelRequest.ChannelType() {
		case "session":
			go func() {
				handleSessionChannel(channelRequest, serverConnection)
				logger.Sugar().Infof("Closing connection from %s", serverConnection.RemoteAddr())
				serverConnection.Close()
				serverConnection = nil
			}()

		default:
			logger.Sugar().Infof("Error: Refusing to open unknown channel type: %s", channelRequest.ChannelType())
			channelRequest.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
}

func handleSessionChannel(channelRequest ssh.NewChannel, conn *ssh.ServerConn) {
	sessionChannel, _, err := channelRequest.Accept()
	if err != nil {
		logger.Sugar().Infof("Could not accept direct-tcpip channel from %s", channelRequest)
		return
	}
	defer sessionChannel.Close()

	term := terminal.NewTerminal(sessionChannel, conn.User()+"@server35:~$ ")

	// Generate the date for the banner
	// Format: Thu Dec 31 15:30:14 GMT 2013
	date := time.Now().Format("Mon Jan 2 15:04:05 MST 2006")

	term.Write([]byte("\r\n"))
	term.Write([]byte("Welcome to Ubuntu 12.04.3 LTS (GNU/Linux 3.8.0-34-generic x86_64)\r\n"))
	term.Write([]byte("\r\n"))
	term.Write([]byte(" * Documentation:  https://help.ubuntu.com/                      \r\n"))
	term.Write([]byte("\r\n"))
	term.Write([]byte("  System information as of " + date + "\r\n"))
	term.Write([]byte("\r\n"))
	term.Write([]byte("  System load:     0.03                IP address for eth0:    10.10.86.42\r\n"))
	term.Write([]byte("  Usage of /:      0.5% of 82.3TB\r\n")) // Tee-hee-hee
	term.Write([]byte("  Memory usage:    3%\r\n"))
	term.Write([]byte("  Swap usage:      0%\r\n"))
	term.Write([]byte("  Processes:       33\r\n"))
	term.Write([]byte("  Users logged in: 1\r\n"))
	term.Write([]byte("\r\n"))
	term.Write([]byte("  Graph this data and manage this system at https://landscape.canonical.com/\r\n"))
	term.Write([]byte("\r\n"))
	term.Write([]byte("394 packages can be updated.\r\n"))
	term.Write([]byte("63 updates are security updates.\r\n"))
	term.Write([]byte("\r\n"))
	term.Write([]byte("Last login: Wed Aug 23 18:28:57 2013 from 10.10.35.1\r\n"))
	term.Write([]byte("\r\n"))

	logFile, err := os.OpenFile(path.Join(cliArgument.LogDir, fmt.Sprintf("ssh-session-%s-%s.log", time.Now().Format("20060102"), hex.EncodeToString(conn.SessionID()))), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		logger.Error("open session log file failed", zap.Error(err))
		return
	}

	sessionLogger := zap.New(
		zapcore.NewTee(
			zapcore.NewCore(zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig()), zapcore.Lock(os.Stderr), zap.DebugLevel),
			zapcore.NewCore(zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig()), zapcore.Lock(logFile), zap.DebugLevel),
		),
		zap.AddCaller(),
		zap.AddStacktrace(zap.ErrorLevel),
		zap.Fields(
			zap.Any("ssh", map[string]interface{}{
				"remote_addr":    conn.RemoteAddr().String(),
				"session_id":     hex.EncodeToString(conn.SessionID()),
				"client_version": fmt.Sprintf("%q", conn.ClientVersion()),
				"server_version": fmt.Sprintf("%q", conn.ServerVersion()),
				"user":           conn.User(),
			})),
	)

	sessionLogger.Info("session started", zap.Time("time", time.Now()))
	sessionLogger.Info("peer address", zap.String("peer", conn.RemoteAddr().String()))

	defer func() {
		sessionLogger.Info("session finished", zap.Time("time", time.Now()))
		sessionLogger.Sync()
	}()

	for {
		line, err := term.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			sessionLogger.Error("Read command failed", zap.Error(err))
		}

		sessionLogger.Info("Record command line input", zap.String("command", line))
		if strings.TrimSpace(line) == "exit" {
			return
		}
	}
}

// generateHostKey Generates a private key and returns it as a byte array
func generateHostKey(bits int) (key []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		logger.Fatal("Could not generate host key", zap.Error(err))
	}

	privateKey.Validate()
	if err != nil {
		logger.Fatal("Could not validate host key", zap.Error(err))
	}

	// Get der format. priv_der []byte
	privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)

	privateKeyBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privateKeyDER,
	}

	// Resultant private key in PEM format.
	return pem.EncodeToMemory(&privateKeyBlock)

}
