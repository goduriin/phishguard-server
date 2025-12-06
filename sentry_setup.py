# sentry_config.py
import os
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration

def init_sentry():
    """
    Инициализация Sentry для мониторинга ошибок.
    
    Отправляет в Sentry:
    - Все исключения (exceptions)
    - HTTP запросы с ошибками
    - Performance данные
    - Release информацию
    """
    
    # Получаем DSN из переменных окружения
    sentry_dsn = os.environ.get('SENTRY_DSN')
    
    # Проверяем, настроен ли DSN
    if not sentry_dsn:
        print("⚠️ Sentry DSN не настроен. Ошибки не будут отслеживаться.")
        print("   Для настройки добавьте SENTRY_DSN в переменные окружения.")
        return False
    
    # Убираем лишние пробелы и кавычки
    sentry_dsn = sentry_dsn.strip().strip('"').strip("'")
    
    print(f"🔧 Configuring Sentry with DSN: {sentry_dsn[:30]}...")
    
    try:
        sentry_sdk.init(
            # === ОСНОВНЫЕ НАСТРОЙКИ ===
            dsn=sentry_dsn,
            integrations=[FlaskIntegration()],
            
            # === PERFORMANCE TRACING ===
            # Включаем трейсинг для 100% запросов
            traces_sample_rate=1.0,
            
            # === ОКРУЖЕНИЕ И РЕЛИЗ ===
            # Определяем окружение (development/staging/production)
            environment=os.environ.get('ENV', 'development'),
            
            # Версия приложения (можно использовать git commit)
            release="phishguard@1.0.0",
            
            # === БЕЗОПАСНОСТЬ И ПРИВАТНОСТЬ ===
            # НЕ отправляем персональные данные (ID пользователей и т.д.)
            send_default_pii=False,
            
            # Уровень детализации для тел запросов
            request_bodies="medium",  # "never", "small", "medium", "always"
            
            # Фильтруем чувствительные данные
            before_send=lambda event, hint: filter_sensitive_data(event),
            
            # === DEBUG НАСТРОЙКИ ===
            # Включаем debug режим если в development
            debug=os.environ.get('ENV') == 'development',
            
            # === ПРОФИЛИРОВАНИЕ ===
            # Включаем profiling (только для production)
            profiles_sample_rate=1.0 if os.environ.get('ENV') == 'production' else 0.0,
            
            # === ОТЛАДКА ===
            # Логируем все что отправляется в Sentry (для отладки)
            # debug=True  # Раскомментируйте для отладки
        )
        
        print("✅ Sentry успешно инициализирован")
        print(f"   Environment: {os.environ.get('ENV', 'development')}")
        print(f"   Release: phishguard@1.0.0")
        
        # Тестируем подключение
        test_sentry_connection()
        
        return True
        
    except Exception as e:
        print(f"❌ Ошибка инициализации Sentry: {e}")
        import traceback
        traceback.print_exc()
        return False

def filter_sensitive_data(event):
    """
    Фильтрует чувствительные данные перед отправкой в Sentry.
    
    Удаляет:
    - API ключи
    - Токены
    - Пароли
    - Личные данные пользователей
    """
    
    # Список чувствительных полей для фильтрации
    SENSITIVE_FIELDS = [
        'password', 'token', 'key', 'secret',
        'api_key', 'api_token', 'access_token',
        'vk_token', 'virustotal_key',
        'authorization', 'cookie',
        'user_id', 'email', 'phone'
    ]
    
    # Фильтруем HTTP запросы
    if 'request' in event:
        # Фильтруем заголовки
        if 'headers' in event['request']:
            for header in list(event['request']['headers'].keys()):
                if any(sensitive in header.lower() for sensitive in SENSITIVE_FIELDS):
                    event['request']['headers'][header] = '[FILTERED]'
        
        # Фильтруем данные формы/JSON
        if 'data' in event['request']:
            if isinstance(event['request']['data'], dict):
                for key in list(event['request']['data'].keys()):
                    if any(sensitive in key.lower() for sensitive in SENSITIVE_FIELDS):
                        event['request']['data'][key] = '[FILTERED]'
    
    # Фильтруем extra данные
    if 'extra' in event:
        for key in list(event['extra'].keys()):
            if any(sensitive in key.lower() for sensitive in SENSITIVE_FIELDS):
                event['extra'][key] = '[FILTERED]'
    
    return event

def test_sentry_connection():
    """Тестирует подключение к Sentry"""
    try:
        # Отправляем тестовое сообщение
        sentry_sdk.capture_message(
            "Sentry подключен успешно",
            level="info"
        )
        print("   Тестовое сообщение отправлено в Sentry")
    except Exception as e:
        print(f"   ⚠️ Не удалось отправить тестовое сообщение: {e}")

def capture_error(error, context=None):
    """Удобная функция для логирования ошибок"""
    try:
        if context:
            sentry_sdk.set_context("phishguard_context", context)
        
        sentry_sdk.capture_exception(error)
        print(f"✅ Ошибка отправлена в Sentry: {type(error).__name__}")
        
    except Exception as e:
        print(f"⚠️ Не удалось отправить ошибку в Sentry: {e}")

def capture_message(message, level="info", context=None):
    """Отправляет сообщение в Sentry"""
    try:
        if context:
            sentry_sdk.set_context("phishguard_context", context)
        
        sentry_sdk.capture_message(message, level)
        print(f"✅ Сообщение отправлено в Sentry: {message[:50]}...")
        
    except Exception as e:
        print(f"⚠️ Не удалось отправить сообщение в Sentry: {e}")