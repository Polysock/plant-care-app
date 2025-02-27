Пример регистрации:
curl -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com", "password":"qwerty123"}'
Пример авторизации:
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com", "password":"qwerty123"}'
Получение информации:
curl -X GET http://localhost:3000/me \
  -H "Authorization: bearer yourtoken"
Выход:
curl -X POST http://localhost:3000/logout \
  -H "Authorization: bearer yourtoken"
