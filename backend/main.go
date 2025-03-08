package main

import (
	"os"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/websocket/v2"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func websocketHandler(c *websocket.Conn) {
	client := &Client{
		conn: c,
		send: make(chan []byte, 256),
	}

	clientsMu.Lock()
	clients[client] = true
	clientsMu.Unlock()

	defer func() {
		clientsMu.Lock()
		delete(clients, client)
		clientsMu.Unlock()
		c.Close()
	}()

	// Запуск readLoop и writeLoop
	go readLoop(client)
	writeLoop(client)
}

type User struct {
	gorm.Model
	Email    string `gorm:"unique"`
	Password string
}

type BlacklistedToken struct {
	gorm.Model
	Token string `gorm:"uniqueIndex;size:255"`
}

type Claims struct {
	UserID uint `json:"user_id"`
	jwt.RegisteredClaims
}

func main() {
	app := fiber.New()
	db := initDB()

	app.Use("/ws", func(c *fiber.Ctx) error {
		if websocket.IsWebSocketUpgrade(c) {
			return c.Next()
		}
		return fiber.ErrUpgradeRequired
	})

	app.Get("/ws", websocket.New(websocketHandler))

	app.Post("/register", registerHandler(db))
	app.Post("/login", loginHandler(db))
	app.Post("/logout", logoutHandler(db))
	app.Get("/me", authMiddleware(db), meHandler(db))
	app.Use(authMiddleware(db))
	app.Post("/plants", createPlantHandler(db))
	app.Get("/plants", listPlantsHandler(db))
	app.Put("/plants/:id", updatePlantHandler(db))
	app.Delete("/plants/:id", deletePlantHandler(db))
	app.Listen(":3000")
	app.Get("/catalog", getCatalogHandler(db))
}

func initDB() *gorm.DB {
	dsn := "host=localhost user=postgres password=postgres dbname=auth_db port=5432 sslmode=disable"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(
		&User{},
		&BlacklistedToken{},
		&Plant{},
		&Reminder{},
	)
	return db
}

// Регистрация
func registerHandler(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		user := new(User)
		if err := c.BodyParser(user); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
		}

		hashed, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Password hashing failed"})
		}

		user.Password = string(hashed)
		if result := db.Create(user); result.Error != nil {
			return c.Status(409).JSON(fiber.Map{"error": "User exists"})
		}

		return c.Status(201).JSON(fiber.Map{"id": user.ID})
	}
}

// Авторизация
func loginHandler(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		credentials := struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}{}

		if err := c.BodyParser(&credentials); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Bad request"})
		}

		var user User
		if result := db.Where("email = ?", credentials.Email).First(&user); result.Error != nil {
			return c.Status(401).JSON(fiber.Map{"error": "Invalid credentials"})
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password)); err != nil {
			return c.Status(401).JSON(fiber.Map{"error": "Invalid credentials"})
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
			UserID: user.ID,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			},
		})

		signedToken, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Token generation failed"})
		}

		return c.JSON(fiber.Map{"token": signedToken})
	}
}

// Выход
func logoutHandler(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := c.Get("Authorization")
		if token == "" {
			return c.Status(400).JSON(fiber.Map{"error": "Missing token"})
		}

		blacklisted := BlacklistedToken{Token: token}
		if result := db.Create(&blacklisted); result.Error != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Logout failed"})
		}

		return c.JSON(fiber.Map{"message": "Successfully logged out"})
	}
}

// Информация о пользователе
func meHandler(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		user := c.Locals("user").(*User)
		return c.JSON(fiber.Map{
			"id":    user.ID,
			"email": user.Email,
		})
	}
}

// Middleware аутентификации
func authMiddleware(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := c.Get("Authorization")
		if token == "" {
			return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
		}

		// Проверка черного списка
		var blacklisted BlacklistedToken
		if result := db.Where("token = ?", token).First(&blacklisted); result.Error == nil {
			return c.Status(401).JSON(fiber.Map{"error": "Token revoked"})
		}

		claims := &Claims{}
		parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})

		if err != nil || !parsed.Valid {
			return c.Status(401).JSON(fiber.Map{"error": "Invalid token"})
		}

		var user User
		if result := db.First(&user, claims.UserID); result.Error != nil {
			return c.Status(401).JSON(fiber.Map{"error": "User not found"})
		}

		c.Locals("user", &user)
		return c.Next()
	}
}

type Plant struct {
	gorm.Model
	UserID        uint      `gorm:"not null" json:"user_id"`
	Name          string    `gorm:"size:255;not null" json:"name"`
	Type          string    `gorm:"size:100" json:"type"`
	WaterSchedule string    `gorm:"size:100;not null" json:"water_schedule"`
	LastWatered   time.Time `json:"last_watered"`
}

type Reminder struct {
	gorm.Model
	PlantID     uint      `json:"plant_id"`
	UserID      uint      `json:"user_id"`
	Title       string    `json:"title"`
	ScheduledAt time.Time `json:"scheduled_at"`
	IsCompleted bool      `json:"is_completed"`
}

func createPlantHandler(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		user := c.Locals("user").(*User)
		plant := new(Plant)

		if err := c.BodyParser(plant); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Bad request"})
		}

		plant.UserID = user.ID
		if result := db.Create(plant); result.Error != nil {
			return c.Status(500).JSON(fiber.Map{"error": "DB error"})
		}

		msg := []byte("Добавлено новое растение: " + plant.Name)
		broadcast(msg)

		return c.Status(201).JSON(plant)
	}
}

func listPlantsHandler(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		user := c.Locals("user").(*User)
		var plants []Plant

		if result := db.Where("user_id = ?", user.ID).Find(&plants); result.Error != nil {
			return c.Status(500).JSON(fiber.Map{"error": "DB error"})
		}

		return c.JSON(plants)
	}
}

type CatalogPlant struct {
	gorm.Model
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	WaterGuide  string `json:"water_guide"`
}

func getCatalogHandler(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var plants []CatalogPlant
		db.Find(&plants)
		return c.JSON(plants)
	}
}

func updatePlantHandler(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		user := c.Locals("user").(*User)
		plantID := c.Params("id")

		var plant Plant
		if result := db.Where("id = ? AND user_id = ?", plantID, user.ID).First(&plant); result.Error != nil {
			return c.Status(404).JSON(fiber.Map{"error": "Plant not found"})
		}

		updates := new(Plant)
		if err := c.BodyParser(updates); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Bad request"})
		}

		db.Model(&plant).Updates(updates)
		return c.JSON(plant)
	}
}

func deletePlantHandler(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		user := c.Locals("user").(*User)
		plantID := c.Params("id")

		var plant Plant
		if result := db.Where("id = ? AND user_id = ?", plantID, user.ID).First(&plant); result.Error != nil {
			return c.Status(404).JSON(fiber.Map{"error": "Plant not found"})
		}

		db.Delete(&plant)
		return c.JSON(fiber.Map{"message": "Plant deleted"})
	}
}

type Client struct {
	conn *websocket.Conn
	send chan []byte
}

var (
	clients   = make(map[*Client]bool)
	clientsMu sync.Mutex
)

func readLoop(c *Client) {
	defer c.conn.Close()
	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			break
		}
	}
}

func writeLoop(c *Client) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			msg := []byte("Проверка состояния растений...")
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case msg := <-c.send:
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		}
	}
}

// Отправка уведомления всем клиентам
func broadcast(message []byte) {
	clientsMu.Lock()
	defer clientsMu.Unlock()

	for client := range clients {
		select {
		case client.send <- message:
		default:
			close(client.send)
			delete(clients, client)
		}
	}
}
