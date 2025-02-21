package main

import (
	"os"

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

type Claims struct {
	UserID uint `json:"user_id"`
	jwt.RegisteredClaims
}

func main() {
	app := fiber.New()
	db := initDB()

	// Auth routes
	app.Post("/register", registerHandler(db))
	app.Post("/login", loginHandler(db))

	// Protected routes
	app.Use(jwtMiddleware())
	app.Get("/plants", getPlantsHandler(db))

	app.Listen(":3000")
}

// Инициализация базы данных
func initDB() *gorm.DB {
	dsn := "host=localhost user=postgres password=postgres dbname=plantcare port=5432 sslmode=disable"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})
	return db
}

// Регистрация пользователя
func registerHandler(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		user := new(User)
		if err := c.BodyParser(user); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not hash password"})
		}

		user.Password = string(hashedPassword)

		if result := db.Create(user); result.Error != nil {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "User already exists"})
		}

		return c.Status(fiber.StatusCreated).JSON(user)
	}
}

// Аутентификация пользователя
func loginHandler(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		credentials := struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}{}

		if err := c.BodyParser(&credentials); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
		}

		var user User
		if result := db.Where("email = ?", credentials.Email).First(&user); result.Error != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password)); err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{
			UserID: user.ID,
		})

		signedToken, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not generate token"})
		}

		return c.JSON(fiber.Map{"token": signedToken})
	}
}

// Middleware для JWT
func jwtMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Missing token"})
		}

		token, err := jwt.Parse(authHeader, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})

		if err != nil || !token.Valid {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Invalid token"})
		}

		return c.Next()
	}
}

// Получение списка растений
func getPlantsHandler(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Пример реализации
		plants := []string{"Ficus", "Monstera", "Cactus"}
		return c.JSON(plants)
	}
}
