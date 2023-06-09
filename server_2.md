
首先，安装所需的依赖项：

```shell
go get -u github.com/gin-gonic/gin
go get -u gorm.io/gorm
go get -u gorm.io/driver/mysql
go get -u github.com/dgrijalva/jwt-go
```

接下来，创建一个名为`main.go`的文件，并将以下代码复制到该文件中：

```go
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/dgrijalva/jwt-go"
)

// User 是用户模型
type User struct {
	ID        uint   `gorm:"primaryKey"`
	Username  string `gorm:"unique"`
	Password  string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Friend 是好友模型
type Friend struct {
	UserID    uint `gorm:"primaryKey"`
	FriendID  uint `gorm:"primaryKey"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Message 是消息模型
type Message struct {
	ID        uint   `gorm:"primaryKey"`
	SenderID  uint
	ReceiverID uint
	Content   string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Group 是群聊模型
type Group struct {
	ID        uint   `gorm:"primaryKey"`
	Name      string `gorm:"unique"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

// GroupMember 是群聊成员模型
type GroupMember struct {
	GroupID   uint `gorm:"primaryKey"`
	UserID    uint `gorm:"primaryKey"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

// AuthMiddleware 是验证中间件
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return []byte("your_secret_key"), nil
		})

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Set("userID", claims["userID"].(float64))
			c.Next()
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
	

}
}

func main() {
	// 连接数据库
	dsn := "your_username:your_password@tcp(your_database_host:your_port)/your_database_name?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	// 迁移数据库
	err = db.AutoMigrate(&User{}, &Friend{}, &Message{}, &Group{}, &GroupMember{})
	if err != nil {
		log.Fatal(err)
	}

	// 创建Gin路由
	r := gin.Default()

	// 用户注册
	r.POST("/register", func(c *gin.Context) {
		var newUser User
		if err := c.ShouldBindJSON(&newUser); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		err := db.Create(&newUser).Error
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, newUser)
	})

	// 用户登录
	r.POST("/login", func(c *gin.Context) {
		var credentials struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := c.ShouldBindJSON(&credentials); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var user User
		err := db.Where("username = ?", credentials.Username).First(&user).Error
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
			return
		}

		if user.Password != credentials.Password {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
			return
		}

		// 创建JWT令牌
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"userID": user.ID,
			"exp":    time.Now().Add(time.Hour * 24).Unix(),
		})

		// 签名令牌
		tokenString, err := token.SignedString([]byte("your_secret_key"))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"token": tokenString})
	})

	// 需要验证和鉴权的路由组
	auth := r.Group("/")
	auth.Use(AuthMiddleware())

	// 获取用户个人资料
	auth.GET("/profile", func(c *gin.Context) {
		userID := uint(c.MustGet("userID").(float64))

		var user User
		err := db.First(&user, userID).Error
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, user)
	})

	// 修改用户个人资料
	auth.PUT("/profile", func(c *gin.Context) {
		userID := uint(c.MustGet("userID").(float64))

		var updatedUser User
		if err := c.ShouldBindJSON(&updatedUser); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		updatedUser.ID = userID
		err := db.Save(&updatedUser).Error
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return


		}

		c.JSON(http.StatusOK, updatedUser)
	})

	// 添加好友
	auth.POST("/friends", func(c *gin.Context) {
		userID := uint(c.MustGet("userID").(float64))

		var friend struct {
			FriendID uint `json:"friendID"`
		}
		if err := c.ShouldBindJSON(&friend); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		friendship := Friend{
			UserID:   userID,
			FriendID: friend.FriendID,
		}

		err := db.Create(&friendship).Error
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, friendship)
	})

	// 发送私信
	auth.POST("/messages", func(c *gin.Context) {
		userID := uint(c.MustGet("userID").(float64))

		var message struct {
			ReceiverID uint   `json:"receiverID"`
			Content    string `json:"content"`
		}
		if err := c.ShouldBindJSON(&message); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		msg := Message{
			SenderID:   userID,
			ReceiverID: message.ReceiverID,
			Content:    message.Content,
		}

		err := db.Create(&msg).Error
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, msg)
	})

	// 创建群聊
	auth.POST("/groups", func(c *gin.Context) {
		userID := uint(c.MustGet("userID").(float64))

		var group Group
		if err := c.ShouldBindJSON(&group); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		tx := db.Begin()

		err := tx.Create(&group).Error
		if err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		member := GroupMember{
			GroupID: group.ID,
			UserID:  userID,
		}

		err = tx.Create(&member).Error
		if err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		err = tx.Commit().Error
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, group)
	})

	// 在群聊发送消息
	auth.POST("/groups/:groupID/messages", func(c *gin.Context) {
		userID := uint(c.MustGet("userID").(float64))
		groupID := c.Param("groupID")

		var message struct {
			Content string `json:"content"`
		}
		if err := c.ShouldBindJSON(&message); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		msg := Message{
			SenderID:  userID,
			Content:   message.Content,
		}

		err := db.Table("group_members").
			Where("group_id = ? AND user_id = ?", groupID, userID).
			First(&GroupMember{}).Error
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User is

 not a member of the group"})
			return
		}

		err = db.Create(&msg).Error
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, msg)
	})

	// 运行服务器
	r.Run(":8080")
}
```

在上面的代码中，您需要替换以下部分：

- `your_username`：您的MySQL数据库用户名
- `your_password`：您的MySQL数据库密码
- `your_database_host`：您的MySQL数据库主机
- `your_port`：您的MySQL数据库端口
- `your_database_name`：您的MySQL数据库名称
- `your_secret_key`：您用于JWT签名的秘钥，请确保它是一个安全的随机字符串

请确保在运行代码之前正确配置MySQL数据库，并确保在运行代码之前安装了所有必需的依赖项。

该示例提供了以下端点：

- `POST /register`：用户注册
- `POST /login`：用户登录，并返回JWT令牌
- `GET /profile`：获取用户个人资料（需要身份验证）
- `PUT /profile`：修改用户个人资料（需要身份验证）
- `POST /friends`：添加好友（需要身份验证）
- `POST /messages`：发送私信（需要身份验证）
- `POST /groups`：创建群聊（需要身份验证）
- `POST /groups/:groupID/messages`：在群聊中发送消息（需要身份验证）

此示例只是一个基本示例，并且没有实现输入验证、错误处理和其他安全性措施。在实际的应用程序中，您需要根据需求进行进一步开发和完善。