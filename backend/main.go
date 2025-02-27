package main

import (
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

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

	app.Post("/register", registerHandler(db))
	app.Post("/login", loginHandler(db))
	app.Post("/logout", logoutHandler(db))
	app.Get("/me", authMiddleware(db), meHandler(db))

	app.Listen(":3000")
}

func initDB() *gorm.DB {
	dsn := "host=localhost user=postgres password=postgres dbname=auth_db port=5432 sslmode=disable"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{}, &BlacklistedToken{})
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
