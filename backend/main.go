// Сервер
package main

import (
	"encoding/json" //Для работы с json, декодирование запроса, кодирование ответа
	"fmt"
	"io"       //Работа с потоками данных
	"log"      //Добавляет время и дату к каждому сообщению
	"net/http" //Здесь вся сеть и функции для сервера
	"secure-gateway/internal/auth"
	"secure-gateway/internal/middleware"
	"strings"
	"sync" //Работа с потокобезопасностью
	"time"
)

// Глобальная конфигурация прокси
var (
	//URL сайта на который проксируем запрос. Изначально строка пуста, но когда пользователь вводит URL и нажимает подключить,
	//то записывается URL. proxyHandler читает эту переменную чтобы знать куда пересылать запрос
	backendURL string
	//Для безопасного доступа из горутин. Гарантирует, что только одна горутина работает с переменной в данный момент
	configMu sync.Mutex
)

// Структура которая описывает что клиент отправляет при входе
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Структура которую мы отправляем клиенту после входа
type LoginResponse struct {
	Token   string `json:"token"`
	Message string `json:"message"`
}

// Структура для конфигурации
type ConfigRequest struct {
	URL string `json:"url"`
}

func main() {
	//Создаем диспетчер запросов(мультиплексор)
	//ServeMux - роутер http запросов, он сопостовляет URL входящего запроса и вызывает обработчик Handler
	mux := http.NewServeMux() //Хранит карту "URL -> Функция"
	//Статические файлы(HTML, CSS, JS)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	//API конфигурации
	mux.HandleFunc("/api/config", configHandler)
	//Публичные пути(не требуют токена). Регистрируем новый обработчик для входа
        mux.HandleFunc("/api/auth/login", loginHandler)
	//Специальные пути шлюза
        mux.HandleFunc("/api/status", statusHandler) //Статус шлюза
	//Защищенные пути(требуют токен)
	mux.HandleFunc("/api/logs", authMiddleware(logsHandler)) //Логи для админки
	mux.HandleFunc("/api/admin/", authMiddleware(adminHandler))

	//Страница настройки
	mux.HandleFunc("/", configPageHandler)

	//Оборачиваем mux в Middleware логирования(все запросы сначала проходят через LoggerMiddleware)
	handler := middleware.LoggerMiddleware(mux)
	//Настройка сервера(&http.Server позволяет детально настроить сервер)
	server := &http.Server{
		Addr:         ":8080",          //Слушать все интерфейсы на порту 8080
		Handler:      handler,          //Обработчик mux обернутый в LoggerMiddleware(кому отдавать запрос)
		ReadTimeout:  10 * time.Second, //Таймаут на чтение запросов(защита от DoS-атаки типа Slowloris)
		WriteTimeout: 10 * time.Second, //Таймаут на запись ответа
	}
	//Вывод сообщения в консоль
	fmt.Println("TM_SAG начал работу на порту 8080...")
	fmt.Println("/api/logs - логи(нужен токен)")
	fmt.Println("/api/auth/login - вход(без токена)")
	fmt.Println("/api/admin/ - админка(нужен токен)")
	//Запуск сервера. ListenAndServer блокирует выполнение программы, пока сервер работает
	//Если сервер упадет, log.Fatal запишет ошибку и остановит программу
	//server.ListenAndServe запускает http сервер с параметрами которые мы указали
	if err := server.ListenAndServe(); err != nil {
		log.Fatal("Ошибка запуска сервера: ", err)
	}
}

// Обработчик страницы настройки
func configPageHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("ЗАПРОС ПОЛУЧЕН")
	http.ServeFile(w, r, "static/index.html")
}

// Обработчик конфигурации(GET/POST)
func configHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	switch r.Method {
	case http.MethodGet:
		//Получение текущей конфигурации
		configMu.Lock()
		connected := backendURL != ""
		url := backendURL
		configMu.Unlock()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"connected": connected,
			"url":       url})

	case http.MethodPost:
		//Обновление конфигурации
		var req ConfigRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Неверный формат"})
			return
		}

		client := &http.Client{
			Timeout: 3 * time.Second, //Ждем максимум 3 секунды	
		}

		resp, err := client.Get(req.URL)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]string{
				"error":"Хост недоступен: " + err.Error(),
			})
			return
		}
		defer resp.Body.Close()

		configMu.Lock()
		backendURL = req.URL
		configMu.Unlock()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"url":     req.URL,
		})

	default:
		http.Error(w, "Только GET/POST", http.StatusMethodNotAllowed)
	}
}

// Функця обработчик входа в систему
func loginHandler(w http.ResponseWriter, r *http.Request) {
	//Проверяем что запрос методом POST. MethodPost - константа со значением POST
	if r.Method != http.MethodPost {
		http.Error(w, "Только POST", http.StatusMethodNotAllowed)
		return
	}
	//Переменная req типа LoginRequest куда кладем данные из запроса
	var req LoginRequest
	//json.NewDecoder(r.Body).Decode(&req) - читаем тело запроса и превращаем JSON в структуру
	//&req - ссылка на переменную, чтобы функция могла ее заполнить. Если ошибка - обрабатываем
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Неверный формат"})
		return
	}
	//Проверка логина и пароля
	if req.Username == "admin" && req.Password == "admin123" {
		//Генерируем токен функцией из пакета auth
		token, err := auth.GenerateToken(req.Username, "admin")
		if err != nil {
			http.Error(w, "Ошибка генерации токена", http.StatusInternalServerError)
			return
		}
		//Устанавливаем заголовок
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		//Структура LoginResponse и отправка клиенту
		//json.NewEncoder(w).Encode(...) - записывает JSON в поток ответа
		json.NewEncoder(w).Encode(LoginResponse{
			Token:   token, //Наш сгенерированный токен
			Message: "Успешный вход",
		})
		return
	}
	//Если лог/пароль неправильные, отправляем JSON с ошибкой, возвращаем
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{"error": "Неверный логин или пароль"})
}

// Функция которая проверяет токен перед основным обработчиком
// Принимает next -  следующий обработчик в цепочке, а возвращает новый обработчик, который сначала проверяет токен потом вызывает next
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	//Возвращаем новую функцию обработчик
	//Суть middleware - оборачиваем один обработчик в другой
	return func(w http.ResponseWriter, r *http.Request) {
		//Получаем заголовок Authorization из запроса
		authHeader := r.Header.Get("Authorization")
		//Если заголовка нет - доступ запрещен
		if authHeader == "" {
			http.Error(w, "Требуется авторизация", http.StatusUnauthorized)
			return
		}
		//Убираем Bearer из заголовка
		//strings.TrimPrefix удаляет начало строки, если оно совпадает
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		//Проверяем токен вызывая функцию из пакеиа auth
		//ValidateToken возвращает расшифрованный claims и ошибку
		claims, err := auth.ValidateToken(tokenString)
		if err != nil {
			http.Error(w, "Неверный токен", http.StatusForbidden)
			return
		}
		//Если токен валиден - добавляем данные пользователя в заголовки запроса
		//Это нужно чтобы следующий обработчик знал кто пришел
		r.Header.Set("X-User-Role", claims.Role)
		r.Header.Set("X-Username", claims.Username)
		//Вызываем следующий обработчик в цепочке
		next(w, r)
	}
}

// Функция обработчик, принимает куда писать ответ(ResponseWriter) и что пришло (Request)
func helloHandler(w http.ResponseWriter, r *http.Request) {
	//Устанавливаем заголовок, что возвращаем текст
	w.Header().Set("Content-Type", "text/plain; charset=utf-8") //Говорим браузеру, что это простой текст, а не скрипт
	//Тело ответа
	fmt.Fprintf(w, "Защищенный шлюз. Время: %s", time.Now().String())
}

// Статус шлюза который возвращает JSON
func statusHandler(w http.ResponseWriter, r *http.Request) {
	//Header - получаем доступ к заголовкам HTTP. Set() - устанавливаем значение заголовка
	w.Header().Set("Content-Type", "application/json; charset=utf-8") //w - краткое имя ResponseWriter
	fmt.Fprintf(w, `{"status": "ok", "service": "gateway", "version": "0.1.0"}`)
}

// Логи заглушка
func logsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	fmt.Fprintf(w, `{"logs": [], "message": "Доступ разрешен для %s"}`, r.Header.Get("X-Username"))
}

// Обработчик для панели админа
func adminHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// Отправляем приветствие с ролью пользователя
	fmt.Fprintf(w, `{"message": "Панель администратора", "role": "%s"}`, r.Header.Get("X-User-Role"))
}

// Proxy-обработчик(пересылает запросы на сайт уника)
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	//Пропускаем запросы к Api шлюза. r.URL.Path - путь запроса
	if r.URL.Path == "/api/status" || r.URL.Path == "/api/logs" {
		http.NotFound(w, r) //Вывод ошибки
		return
	}

	//Берем URL из конфигурации
	configMu.Lock()
	currentURL := backendURL
	configMu.Unlock()

	if currentURL == "" {
		http.Error(w, "Сайт не подключен. Откройте / для настройки", 503)
		return
	}
	//Формируем URL для сайта(порт 8081) и заменяем порт 8080 на 8080 для внутреннего запроса
	targetURL := currentURL + r.URL.Path
	//NewRequest - создаем новый запрос на сайт
	newReq, err := http.NewRequest(r.Method, targetURL, r.Body) //Метод оригинала(GET, POST), куда отправлять и тело запроса(POST)
	if err != nil {
		http.Error(w, "Ошибка создания запроса на сайт", http.StatusInternalServerError)
		return
	}
	//Копируем заголовки оригинального запроса чтобы сайт получил всю информацию от пользователя
	//Сайт получит формат данных, кто пользователь и какой браузер
	for key, values := range r.Header {
		for _, value := range values {
			newReq.Header.Add(key, value) //Добавляет заголовок в новый запрос
		}
	}
	//Добавляем заголовок безопасности, если нет заголовка сайт отклонит запрос
	newReq.Header.Set("X-Forwarded-By", "Secure-Gateway")
	//Отправляем запрос на сайт, создаем пустой клиент
	client := &http.Client{}
	//resp = *http.Response(Ответ от сайта). Client.Do - отправляет запрос и ждет ответ. newReq - что отправляем
	resp, err := client.Do(newReq)
	if err != nil {
		http.Error(w, "Сайт недоступен", http.StatusBadGateway)
		return
	}
	//defer - отложенное выполнение(откроется перед выходом из фуекции)
	defer resp.Body.Close() //Закрывает поток ответа
	//Копируем заголовки ответа от сайта, сайт отправляет заголовки и клиент их получает
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value) //Добавляем ответ клиенту
		}
	}
	//Устанавливаем статус код
	w.WriteHeader(resp.StatusCode)
	//Копируем тело ответа от сайта пользователю
	_, err = io.Copy(w, resp.Body) //io.Copy - копируем поток данных. w - куда ответ. resp.Body - откуда ответ
	if err != nil {
		log.Printf("Ошибка копирования ответа: %v", err)
	}
}
