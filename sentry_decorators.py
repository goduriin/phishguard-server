# sentry_decorators.py
import functools
import time
from flask import request
import sentry_sdk

def track_performance(name=None):
    """
    Декоратор для трекинга производительности функций.
    
    Отправляет в Sentry:
    - Время выполнения функции
    - Успешность выполнения
    - Контекст вызова
    """
    
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Создаем транзакцию для отслеживания
            transaction_name = name or f"{func.__module__}.{func.__name__}"
            
            with sentry_sdk.start_transaction(op="function", name=transaction_name) as transaction:
                try:
                    start_time = time.time()
                    
                    # Выполняем функцию
                    result = func(*args, **kwargs)
                    
                    # Записываем время выполнения
                    duration = time.time() - start_time
                    transaction.set_measurement("duration", duration, "seconds")
                    
                    # Добавляем теги
                    transaction.set_tag("function", func.__name__)
                    transaction.set_tag("module", func.__module__)
                    
                    # Устанавливаем статус
                    transaction.finish(status="ok")
                    
                    return result
                    
                except Exception as e:
                    # При ошибке записываем в транзакцию
                    transaction.set_tag("error", "true")
                    transaction.finish(status="internal_error")
                    
                    # Передаем ошибку дальше
                    raise
        
        return wrapper
    return decorator

def sentry_trace_requests(func):
    """
    Декоратор для трекинга HTTP запросов.
    
    Автоматически добавляет:
    - Endpoint
    - Метод
    - Статус код
    - Время выполнения
    """
    
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Начинаем транзакцию для HTTP запроса
        with sentry_sdk.start_transaction(
            op="http.server",
            name=f"{request.method} {request.path}"
        ) as transaction:
            try:
                # Добавляем контекст запроса
                transaction.set_context("request", {
                    "method": request.method,
                    "url": request.url,
                    "path": request.path,
                    "query_string": request.query_string.decode() if request.query_string else None,
                    "remote_addr": request.remote_addr,
                })
                
                # Устанавливаем теги
                transaction.set_tag("http.method", request.method)
                transaction.set_tag("http.route", request.path)
                transaction.set_tag("http.user_agent", request.user_agent.string[:100] if request.user_agent else None)
                
                start_time = time.time()
                
                # Выполняем функцию
                response = func(*args, **kwargs)
                
                # Получаем статус код
                if isinstance(response, tuple):
                    status_code = response[1]
                else:
                    status_code = 200
                
                # Записываем время выполнения
                duration = time.time() - start_time
                transaction.set_measurement("duration", duration, "seconds")
                
                # Устанавливаем тег статуса
                transaction.set_tag("http.status_code", status_code)
                
                # Определяем успешность по статус коду
                if 200 <= status_code < 400:
                    transaction.finish(status="ok")
                else:
                    transaction.set_tag("error", "true")
                    transaction.finish(status=status_code)
                
                return response
                
            except Exception as e:
                # При исключении отмечаем ошибку
                transaction.set_tag("error", "true")
                transaction.set_tag("exception_type", type(e).__name__)
                transaction.finish(status="internal_error")
                raise
    
    return wrapper