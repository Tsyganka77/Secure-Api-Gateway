//Работа с токенами доступа(JWT)
package auth

import (
	"errors"    //Для создания ошибок типа(неверный токен)
	"time"
	"github.com/golang-jwt/jwt/v5"    //Сторонняя библиотека для работы с JWT
)
//Секретный ключ для подписи токенов
var SecretKey = []byte("sarfti-secure-gateway-2026")
//Claims - структура данных которая вшита внутрь токена, когда его расшифруют, данные станут доступными
type Claims struct{
	Username string `json:"username"`    //Говорим как назвать поле в JSON
	Role string `json:"role"`
	//Встраиваем стандартные поля JWT(срок действия, время выпуска и т.д.)
	jwt.RegisteredClaims
}
//Функция которая создает токен для пользователя
//Принимает имя и роль, возвращает токен и ошибку(если что то пошло не так)
func GenerateToken(username, role string)(string, error){
	//Создаем экземпляр структуры Claims с даннымипользователя
	claims := Claims{
		Username:username,
		Role:role,
		RegisteredClaims: jwt.RegisteredClaims{
			//Токен действует 24 часа с момента создания
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24*time.Hour)),
			//Время выпуска токена - сейчас
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}
	//Создаем новый токен используя алгоритм шифрования HS256
	//NewWithClaims - функция, которая упаковывает claims в токен
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	//Подписываем токен нашим секретным ключом
	//SignedString - возвращает готовую строку токен
	return token.SignedString(SecretKey)
}
//Функция которая проверяет токен. На вход принимаем токен от клиента(tokenString) и возвращаем расшифрованные данные
func ValidateToken(tokenString string)(*Claims, error){
	//Расшифровываем токен. ParseWithClaims - берет строку токена, расшифровывает ее в структуру *Claims, 
	//использует нашу функцию для получения ключа(SecretKey)
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token)(interface{},error){
		return SecretKey, nil    //Возвращаем ключ для проверки подписи
	})
	if err != nil{
		return nil, err
	}
	//Приводим интерфейс токена к типу *claims, если все хорошо, ok выведет true
	claims, ok := token.Claims.(*Claims)
	//Ошибка если не смогли привести или токен не валиден
	if !ok || !token.Valid {
		return nil, errors.New("Неверный токен")
	}
	//Если все ок - возвращаем расшифрованные данные
	return claims, nil
}
