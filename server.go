package main

import (
	"fmt"
	"net"
	"strings"
)

// Client 表示一个客户端的连接
type Client struct {
	conn     net.Conn
	username string
}

// ChatServer 表示聊天室服务端
type ChatServer struct {
	clients []*Client
}

// Broadcast 广播消息
func (s *ChatServer) Broadcast(msg string, sender *Client) {
	for _, client := range s.clients {
		// 不发送给自己
		if client != sender {
			client.conn.Write([]byte(msg))
		}
	}
}

// HandleConnection 处理单个连接
func (s *ChatServer) HandleConnection(conn net.Conn) {
	// 创建客户端
	client := &Client{conn: conn}

	// 保存客户端
	s.clients = append(s.clients, client)

	// 发送提示信息
	msg := "欢迎加入聊天室！请输入你的用户名：\n"
	conn.Write([]byte(msg))

	// 循环接收客户端信息
	for {
		// 读取消息
		buffer := make([]byte, 1024)
		bytesRead, err := conn.Read(buffer)
		if err != nil {
			// 客户端断开
			// 从客户端列表中移除断开的连接
			index := -1
			for i, c := range s.clients {
				if c.conn == conn {
					index = i
					break
				}
			}
			if index != -1 {
				s.clients = append(s.clients[:index], s.clients[index+1:]...)
			}
			// 广播其他客户端
			msg := fmt.Sprintf("%s 离开了聊天室\n", client.username)
			s.Broadcast(msg, nil)
			// 实时更新在线人数
			s.Broadcast(fmt.Sprintf("当前在线人数：%d\n", len(s.clients)), nil)
			break
		}

		// 处理消息
		msg := strings.TrimSpace(string(buffer[:bytesRead]))
		if client.username == "" {
			// 新用户输入用户名
			if len(msg) > 0 && len(msg) < 20 {
				client.username = msg
				// 广播其他客户端
				msg := fmt.Sprintf("%s 加入了聊天室\n", client.username)
				s.Broadcast(msg, nil)
				// 实时更新在线人数
				s.Broadcast(fmt.Sprintf("当前在线人数：%d\n", len(s.clients)), nil)
			} else {
				// 用户名无效
				conn.Write([]byte("用户名无效，请重新输入：\n"))
			}
		} else {
			// 已经输入过用户名，则处理聊天消息
			if msg == "/online" {
				// 查询在线人数
				online := len(s.clients)
				conn.Write([]byte(fmt.Sprintf("当前在线人数：%d\n", online)))
			} else if strings.HasPrefix(msg, "/rename ") {
				// 改名
				newName := strings.TrimSpace(strings.TrimPrefix(msg, "/rename "))
				if len(newName) > 0 && len(newName) < 20 {
					oldName := client.username
					// 检查新用户名是否重复
					duplicate := false
					for _, c := range s.clients {
						if c.username == newName {
							duplicate = true
							break
						}
					}
					if !duplicate {
						client.username = newName
						// 广播其他客户端
						msg := fmt.Sprintf("%s 改名为 %s\n", oldName, newName)
						s.Broadcast(msg, nil)
					} else {
						// 新用户名重复
						conn.Write([]byte("新用户名重复，请重新输入：\n"))
					}
				} else {
					// 新用户名无效
					conn.Write([]byte("新用户名无效，请重新输入：\n"))
				}
			} else if strings.HasPrefix(msg, "/msg ") {
				// 私聊
				parts := strings.Split(strings.TrimPrefix(msg, "/msg "), " ")
				if len(parts) > 1 {
					targetName := parts[0]
					msg := strings.Join(parts[1:], " ")
					targetFound := false
					for _, c := range s.clients {
						if c.username == targetName {
							targetFound = true
							// 发送私聊消息
							c.conn.Write([]byte(fmt.Sprintf("%s 对你私聊：%s\n", client.username, msg)))
							conn.Write([]byte(fmt.Sprintf("你对 %s 私聊：%s\n", targetName, msg)))
							break
						}
					}
					if !targetFound {
						// 没有找到目标用户
						conn.Write([]byte(fmt.Sprintf("未找到用户 %s\n", targetName)))
					}
				} else {
					// 没有输入消息内容
					conn.Write([]byte("私聊消息格式不正确，请重新输入：\n"))
				}
			} else if len(msg) > 0 {
				// 发送聊天消息
				msg := fmt.Sprintf("%s 说：%s\n", client.username, msg)
				s.Broadcast(msg, client)
			}
		}
	}
}

// Start 启动服务端
func (s *ChatServer) Start() {
	// 开启监听
	listen, err := net.Listen("tcp", "127.0.0.1:8888")
	if err != nil {
		fmt.Println("error listening:", err.Error())
		return
	}
	fmt.Println("server started on 127.0.0.1:8888")

	// 接收连接
	for {
		conn, err := listen.Accept()
		if err != nil {
			fmt.Println("error accepting:", err.Error())
			continue
		}
		// 处理连接
		go s.HandleConnection(conn)
	}
}

// NewChatServer 创建一个新的聊天室服务端
func NewChatServer() *ChatServer {
	return &ChatServer{
		clients: []*Client{},
	}
}

func main() {
	// 创建聊天室服务端并启动
	NewChatServer().Start()
}
