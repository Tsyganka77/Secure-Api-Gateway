//Модуль отвечающий за логи(Журнал событий программы)
package middleware

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)
//Функция которая оборачивает другой обработчик
func LoggerMiddleware(next http.Handler) http.Handler {
	//Открываем файл для записи логов. os.O_APPEND: дописывать в конец файла, не стирая старое
	//os.O_CREATE: создать файл, если его нет. os.O_WRONLY: только запись
	file, err := os.OpenFile("logs/access.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)    //0644-права доступа к файлу
	if err != nil{
		log.Fatalf("Не удалось открыть логи: %v", err)
	}
	//Новая функция обработчик
	return http.HandlerFunc(func(w http.ResponseWriter, r*http.Request){
		//Запоминаем время начала запроса
		start := time.Now()
		//Передаем управление к основной логике(к helloHandler)
		next.ServeHTTP(w,r)
		//Вычисляем длительность запроса
		duration := time.Since(start)
		//Формируем логи в формате JSON
		logEntry := fmt.Sprintf("{\"time\":\"%s\",\"ip\":\"%s\",\"method\":\"%s\",\"path\":\"%s\",\"duration\":\"%s\"}\n",
			start.Format(time.RFC3339),
			r.RemoteAddr,
			r.Method,
			r.URL.Path,
			duration.String(),
		)
		//Запись в файл
		_, err := file.WriteString(logEntry)    //Запись байтов на диск
		if err != nil {
			log.Printf("Ошибка записи в лог: %v", err)
		}
		//Дублирую в консоль
		fmt.Printf("Log: %s %ss [%s]\n", r.Method, r.URL.Path, duration.String())
	})
}
