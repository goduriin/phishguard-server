from flask import Flask, request, jsonify
import requests
import os
import json 
from datetime import datetime
from flask_cors import CORS
import hmac
import hashlib
import time
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
from collections import defaultdict
from threading import Lock
from werkzeug.middleware.proxy_fix import ProxyFix
from urllib.parse import urlparse, urljoin

app = Flask(__name__)

# ==================== ПРОДАКШЕН CORS КОНФИГУРАЦИЯ ====================
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

def check_origin_allowed(origin):
    """Проверяет разрешен ли origin для CORS"""
    ALLOWED_DOMAINS = [
        "vk.com",
        "vk.ru",
        "phishguard-server-production.up.railway.app",
        "localhost",
        "127.0.0.1",
    ]
    
    if not origin:
        return True
    
    try:
        parsed = urlparse(origin)
        domain = parsed.netloc
        
        if ':' in domain:
            domain = domain.split(':')[0]
        
        if domain in ALLOWED_DOMAINS:
            return True
        
        if domain.endswith('.vk.com') or domain.endswith('.vk.ru'):
            return True
            
        return False
        
    except Exception:
        return False

# НАСТРОЙКА CORS
CORS(app, resources={r"/*": {
    "origins": [
        "https://vk.com",
        "https://vk.ru", 
        "https://phishguard-server-production.up.railway.app",
        "http://localhost:*",
        "http://127.0.0.1:*"
    ],
    "methods": ["GET", "POST", "OPTIONS"],
    "allow_headers": [
        "Content-Type", 
        "Authorization", 
        "X-Secret-Key", 
        "X-Signature", 
        "X-Timestamp",
        "X-Requested-With",
        "Accept"
    ],
    "expose_headers": [
        "Content-Type", 
        "X-RateLimit-Limit", 
        "X-RateLimit-Remaining",
        "X-RateLimit-Reset"
    ],
    "supports_credentials": False,
    "max_age": 600
}})

# ==================== SECURITY HEADERS ====================
@app.after_request
def add_security_headers(response):
    """Добавляет security headers для продакшена"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    if request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    
    return response

# ==================== КОНФИГУРАЦИЯ ====================
VK_TOKEN = os.environ.get('VK_TOKEN')
SECRET_KEY = os.environ.get('SECRET_KEY', 'phishguard_secret_key_2024')
HMAC_SECRET_KEY = os.environ.get('HMAC_SECRET_KEY', 'phishguard_hmac_secret_2024')
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')

# Глобальные переменные для статистики
stats = {
    'total_checks': 0,
    'malicious_count': 0,
    'users': set(),
    'last_check': None,
    'malicious_links': [],
    'link_history': []
}

stats_lock = Lock() 

# ==================== HMAC ФУНКЦИИ (ИСПРАВЛЕННЫЕ) ====================
def deep_sort_dict(obj):
    """Рекурсивно сортирует ключи словаря ТОЧНО как в клиенте"""
    if isinstance(obj, dict):
        # Сортируем ключи и рекурсивно обрабатываем значения
        result = {}
        for key in sorted(obj.keys()):
            result[key] = deep_sort_dict(obj[key])
        return result
    elif isinstance(obj, list):
        # Обрабатываем каждый элемент списка
        return [deep_sort_dict(item) for item in obj]
    else:
        # Примитивные типы возвращаем как есть
        return obj

def generate_hmac_signature(data, timestamp):
    """Генерирует HMAC подпись ТОЧНО как в клиенте"""
    try:
        print(f"\n🔍 SERVER HMAC GENERATION:")
        print(f"  Timestamp: {timestamp}")
        print(f"  Original data keys: {list(data.keys()) if isinstance(data, dict) else 'not dict'}")
        
        # КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ:
        # ТОЧНО как в клиенте: создаем новый объект с отсортированными ключами
        if not data:
            print("❌ No data for HMAC")
            return None
            
        # 1. Сортируем ключи (ТОЧНО как в клиенте)
        if isinstance(data, dict):
            # Рекурсивно сортируем все вложенные объекты
            sorted_data = deep_sort_dict(data)
            print(f"  Sorted keys: {list(sorted_data.keys())}")
        else:
            sorted_data = data
        
        # 2. JSON строка (ТОЧНО как в клиенте: JSON.stringify(sortedData))
        # Используем separators=(',', ':') чтобы убрать лишние пробелы
        data_str = json.dumps(sorted_data, separators=(',', ':'))
        print(f"  Data JSON (first 100): {data_str[:100]}...")
        print(f"  Data JSON length: {len(data_str)}")
        
        # 3. Сообщение: timestamp + dataStr + secret (ТОЧНО как в клиенте!)
        message = str(timestamp) + data_str + HMAC_SECRET_KEY
        print(f"  Message (first 100): {message[:100]}...")
        print(f"  Message length: {len(message)}")
        
        # 4. HMAC-SHA256
        signature = hmac.new(
            HMAC_SECRET_KEY.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        print(f"  Generated signature: {signature[:50]}...")
        print(f"  Signature length: {len(signature)}")
        
        return signature
        
    except Exception as e:
        print(f"❌ SERVER HMAC generation error: {e}")
        import traceback
        traceback.print_exc()
        return None

def verify_hmac_signature(data, signature, timestamp, max_age=600):
    """Проверяет HMAC подпись с подробной отладкой"""
    try:
        print(f"\n=== HMAC VERIFICATION ===")
        print(f"  Path: {request.path}")
        print(f"  Timestamp: {timestamp}")
        
        if data and isinstance(data, dict):
            print(f"  Data keys ({len(data)}): {list(data.keys())}")
        
        print(f"  Received signature: {signature[:50]}..." if signature else "  No signature!")
        
        # 1. Базовые проверки
        if not signature or not timestamp:
            print("❌ Missing signature or timestamp")
            return False
        
        # 2. Проверяем timestamp
        try:
            ts = float(timestamp)
            if ts > 1000000000000:  # Если timestamp в миллисекундах
                ts_seconds = ts / 1000.0
                print(f"  Timestamp in ms: {ts} -> seconds: {ts_seconds}")
            else:
                ts_seconds = ts
                print(f"  Timestamp in seconds: {ts}")
        except ValueError:
            print("❌ Invalid timestamp format")
            return False
        
        # 3. Проверяем свежесть (10 минут для надежности)
        current_time = time.time()
        time_diff = abs(current_time - ts_seconds)
        print(f"  Current server time: {current_time}")
        print(f"  Time difference: {time_diff:.1f} seconds")
        
        if time_diff > max_age:
            print(f"❌ Request too old: {time_diff:.1f}s > {max_age}s")
            return False
        
        # 4. Генерируем ожидаемую подпись
        expected = generate_hmac_signature(data, timestamp)
        
        if not expected:
            print("❌ Failed to generate expected signature")
            return False
        
        print(f"  Expected signature: {expected[:50]}...")
        
        # 5. Сравниваем
        match = signature == expected
        print(f"  Signatures match: {match}")
        
        if not match:
            print("🔍 DEBUG: Checking differences...")
            print(f"  Received length: {len(signature)}")
            print(f"  Expected length: {len(expected)}")
            
            # Поиск различий
            min_len = min(len(signature), len(expected))
            for i in range(min_len):
                if signature[i] != expected[i]:
                    print(f"  First diff at position {i}: '{signature[i]}' != '{expected[i]}'")
                    print(f"  Received chunk: {signature[i:i+10]}")
                    print(f"  Expected chunk: {expected[i:i+10]}")
                    break
        
        return hmac.compare_digest(signature, expected)
        
    except Exception as e:
        print(f"❌ HMAC verification error: {e}")
        import traceback
        traceback.print_exc()
        return False

# ==================== DEBUG HMAC ENDPOINT ====================
@app.route('/api/debug-hmac', methods=['POST', 'OPTIONS'])
def debug_hmac():
    """Endpoint для отладки HMAC"""
    try:
        if request.method == 'OPTIONS':
            return jsonify({"status": "ok"}), 200
            
        data = request.json
        signature = request.headers.get('X-Signature')
        timestamp = request.headers.get('X-Timestamp')
        
        print(f"\n=== HMAC DEBUG ENDPOINT ===")
        print(f"Timestamp: {timestamp}")
        print(f"Signature: {signature[:50] if signature else 'None'}...")
        
        # Генерируем подпись на сервере
        server_signature = generate_hmac_signature(data, timestamp)
        
        return jsonify({
            "match": signature == server_signature,
            "client_signature": signature,
            "server_signature": server_signature,
            "timestamp": timestamp,
            "debug": {
                "data_keys": list(data.keys()) if data else [],
                "timestamp_type": type(timestamp).__name__,
                "message_example": f"{timestamp}{json.dumps(data, sort_keys=True)[:50]}..."
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def hmac_required(f):
    """Декоратор для проверки HMAC"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Пропускаем OPTIONS запросы
        if request.method == 'OPTIONS':
            return f(*args, **kwargs)
            
        # Пропускаем health check
        if request.path in ['/health', '/']:
            return f(*args, **kwargs)
            
        try:
            signature = request.headers.get('X-Signature')
            timestamp = request.headers.get('X-Timestamp')
            
            print(f"🔍 Checking HMAC for {request.path}")
            
            # Если нет HMAC заголовков, проверяем старый способ
            if not signature or not timestamp:
                print("⚠️ No HMAC headers, checking legacy auth")
                client_secret = request.headers.get('X-Secret-Key')
                if client_secret and client_secret == SECRET_KEY:
                    print("✅ Legacy authentication successful")
                    return f(*args, **kwargs)
                return jsonify({"error": "HMAC signature required"}), 401
            
            # Проверяем HMAC
            if verify_hmac_signature(request.json, signature, timestamp):
                print(f"✅ HMAC verified for {request.path}")
                return f(*args, **kwargs)
            else:
                print(f"❌ Invalid HMAC signature for {request.path}")
                return jsonify({"error": "Invalid HMAC signature"}), 401
                
        except Exception as e:
            print(f"❌ HMAC middleware error: {e}")
            return jsonify({"error": "Authentication error"}), 401
    
    return decorated_function

# ==================== RATE LIMITING ====================
class RateLimiter:
    def __init__(self):
        self.requests = defaultdict(list)
        self.lock = Lock()
        
        self.limits = {
            '/api/check-result': {'limit': 100, 'window': 3600},
            '/api/report-link': {'limit': 500, 'window': 3600},
            '/vk-callback': {'limit': 1000, 'window': 3600},
        }
    
    def is_allowed(self, endpoint, ip_address):
        if endpoint not in self.limits:
            return True
        
        with self.lock:
            current_time = time.time()
            limit_config = self.limits[endpoint]
            
            window_start = current_time - limit_config['window']
            self.requests[ip_address] = [
                req_time for req_time in self.requests[ip_address]
                if req_time > window_start
            ]
            
            if len(self.requests[ip_address]) >= limit_config['limit']:
                return False
            
            self.requests[ip_address].append(current_time)
            return True

limiter = RateLimiter()

def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not limiter.is_allowed(request.path, request.remote_addr):
            return jsonify({
                'error': 'Rate limit exceeded',
                'retry_after': 60
            }), 429
        return f(*args, **kwargs)
    return decorated_function

# ==================== ЛОГИРОВАНИЕ ====================
def setup_logging():
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    file_handler = RotatingFileHandler(
        'logs/app.log',
        maxBytes=10*1024*1024,
        backupCount=5
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    
    error_handler = RotatingFileHandler(
        'logs/errors.log',
        maxBytes=5*1024*1024,
        backupCount=3
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger()
    logger.addHandler(file_handler)
    logger.addHandler(error_handler)
    
    return logger

logger = setup_logging()

# ==================== ENDPOINTS ====================
@app.route('/')
def home():
    return jsonify({
        "status": "PhishGuard Server is running!",
        "version": "1.0",
        "timestamp": datetime.now().isoformat(),
        "security": "HMAC authentication enabled"
    })

@app.route('/health')
def health():
    return jsonify({
        "status": "healthy",
        "server": "PhishGuard",
        "timestamp": datetime.now().isoformat()
    }), 200

@app.route('/api/hmac-test', methods=['POST'])
@hmac_required
def hmac_test():
    """Тестовый endpoint для проверки HMAC"""
    try:
        return jsonify({
            "status": "success",
            "message": "HMAC verification successful",
            "timestamp": request.headers.get('X-Timestamp'),
            "hmac_verified": True
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# OPTIONS handlers
@app.route('/api/check-result', methods=['OPTIONS'])
def options_check_result():
    return jsonify({"status": "ok"}), 200

@app.route('/api/report-link', methods=['OPTIONS'])
def options_report_link():
    return jsonify({"status": "ok"}), 200

@app.route('/api/check-result', methods=['POST'])
@hmac_required
@rate_limit
def handle_check_result():
    """Принимает результаты проверки от расширения (с HMAC)"""
    try:
        data = request.json
        logger.info(f"Received HMAC-protected check result from user {data.get('user_id', 'unknown')}")
        
        # Обновляем статистику
        stats['total_checks'] += 1
        if data.get('user_id'):
            stats['users'].add(data.get('user_id'))
        stats['last_check'] = datetime.now().isoformat()
        
        user_id = data['user_id']
        url = data['url']
        is_malicious = data.get('is_malicious', False)
        
        if is_malicious:
            stats['malicious_count'] += 1
            
            malicious_data = {
                'url': url,
                'domain': extract_domain(url),
                'timestamp': datetime.now().isoformat(),
                'user_id': user_id
            }
            stats['malicious_links'].append(malicious_data)
            
            if len(stats['malicious_links']) > 50:
                stats['malicious_links'] = stats['malicious_links'][-50:]
            
            # Формируем сообщение
            original_url = data.get('original_url', url)
            final_url = data.get('final_url', url)
            is_vk_redirect = data.get('is_vk_redirect', False)
            
            if is_vk_redirect:
                message = f"""🚨 ФИШИНГ ОБНАРУЖЕН!

⚠️ ВНИМАНИЕ: Ссылка была замаскирована под VK!

📌 Маскированная ссылка: {original_url}
🔗 Настоящая ссылка: {final_url}
🌐 Домен: {extract_domain(final_url)}
🕒 Время обнаружения: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}

🚫 НЕ ПЕРЕХОДИТЕ по этой ссылке!
🎭 Это фишинг, замаскированный под ссылку VK!"""
            else:
                message = f"""🚨 ФИШИНГ ОБНАРУЖЕН!

📌 Опасная ссылка: {url}
🌐 Домен: {extract_domain(url)}
🕒 Время обнаружения: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}

🚫 НЕ ПЕРЕХОДИТЕ по этой ссылке!
⚠️ Это может быть фишинг или мошенничество!"""
            
            success = send_vk_message(user_id, message, get_main_keyboard())
            
            if success:
                logger.info(f"Sent VK notification to user {user_id}")
                return jsonify({
                    "status": "success", 
                    "malicious_detected": True,
                    "notification_sent": True
                })
            else:
                logger.error(f"Failed to send VK notification to user {user_id}")
                return jsonify({"error": "Failed to send VK message"}), 500
        else:
            logger.info(f"Safe link from user {user_id}: {url}")
            return jsonify({
                "status": "success", 
                "malicious_detected": False,
                "message": "Link is safe"
            })
        
    except Exception as e:
        logger.error(f"Error in check-result: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/report-link', methods=['POST'])
@hmac_required
@rate_limit
def handle_link_report():
    """Принимает отчеты о ссылках (с HMAC)"""
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        logger.info(f"Received HMAC-protected link report from user {data.get('user_id', 'unknown')}")
        
        # Обновляем статистику
        with stats_lock:  # Используем блокировку для потокобезопасности
            stats['total_checks'] += 1
            if data.get('user_id'):
                stats['users'].add(data.get('user_id'))
            stats['last_check'] = datetime.now().isoformat()
            
            # Сохраняем в историю
            link_data = {
                'url': data.get('original_url'),
                'final_url': data.get('final_url'),
                'domain': extract_domain(data.get('final_url', data.get('original_url'))),
                'timestamp': datetime.now().isoformat(),
                'source': data.get('source', 'unknown'),
                'user_id': data.get('user_id'),
                'is_malicious': data.get('is_malicious', False),
                'is_vk_redirect': data.get('is_vk_redirect', False),
                'is_external': data.get('is_external', False),
                'report_type': data.get('report_type', 'all_links')
            }
            
            stats['link_history'].append(link_data)
            
            if len(stats['link_history']) > 500:
                stats['link_history'] = stats['link_history'][-500:]
        
        # Получаем данные для проверки дубликатов
        is_malicious = link_data['is_malicious']
        domain = link_data['domain']
        
        # Логируем тип ссылки
        if link_data.get('is_vk_redirect'):
            link_type = "VK маскированная"
        elif domain and ('vk.com' in domain or 'vk.' in domain):
            link_type = "VK внутренняя"
        else:
            link_type = "Внешняя"
            
        logger.info(f"Saved {link_type} link: {domain}")
        
        # ПРОСТАЯ ПРОВЕРКА ДУБЛИКАТОВ (опционально)
        if is_malicious:
            # Ищем похожие фишинговые ссылки за последний час
            one_hour_ago = datetime.now().timestamp() - 3600
            with stats_lock:
                recent_phishing = [
                    link for link in stats['link_history'][-50:]
                    if link.get('is_malicious') 
                    and datetime.fromisoformat(link['timestamp'].replace('Z', '+00:00')).timestamp() > one_hour_ago
                ]
            
            if len(recent_phishing) > 10:  # Если много фишинга за час
                logger.info(f"⚠️ Много фишинга: {len(recent_phishing)} за час")
        
        return jsonify({
            "status": "success", 
            "message": "Link saved to statistics",
            "link_type": link_type,
            "total_links": len(stats['link_history']),
            "hmac_verified": True
        })
        
    except Exception as e:
        logger.error(f"Link report error: {e}")
        return jsonify({"error": "Internal server error"}), 500

def extract_domain(url):
    """Извлекает домен из URL"""
    try:
        return urlparse(url).hostname
    except:
        return "invalid_url"

# Клавиатуры для бота
def get_main_keyboard():
    """Клавиатура для VK бота (рабочая версия)"""
    return {
        "one_time": False,
        "buttons": [
            [
                {
                    "action": {
                        "type": "text",
                        "payload": "{\"command\":\"help\"}",
                        "label": "🛡️ Помощь"
                    },
                    "color": "primary"
                }
            ],
            [
                {
                    "action": {
                        "type": "text",
                        "payload": "{\"command\":\"stats\"}",
                        "label": "📊 Статистика"
                    },
                    "color": "positive"
                }
            ],
            [
                {
                    "action": {
                        "type": "text",
                        "payload": "{\"command\":\"all_links\"}",
                        "label": "🔗 Все ссылки"
                    },
                    "color": "primary"
                }
            ],
            [
                {
                    "action": {
                        "type": "text",
                        "payload": "{\"command\":\"malicious_links\"}",
                        "label": "🚫 Опасные ссылки"
                    },
                    "color": "negative"
                }
            ]
        ]
    }
 
def send_vk_message(user_id, message, keyboard=None):
    """Отправляет сообщение через VK API (продакшен версия)"""
    try:
        logger.info(f"📨 Отправка сообщения пользователю {user_id}")
        
        params = {
            'user_id': int(user_id),
            'message': message,
            'random_id': int(datetime.now().timestamp() * 1000),
            'access_token': VK_TOKEN,
            'v': '5.199'
        }
        
        if keyboard:
            # Важно: не использовать ensure_ascii=False для VK API
            params['keyboard'] = json.dumps(keyboard)
            logger.debug(f"Клавиатура добавлена: {len(params['keyboard'])} символов")
        
        response = requests.post(
            'https://api.vk.com/method/messages.send',
            data=params,
            timeout=10
        )
        
        result = response.json()
        logger.info(f"VK API ответ: {result}")
        
        if 'error' in result:
            error = result['error']
            error_code = error.get('error_code')
            error_msg = error.get('error_msg')
            
            logger.error(f"❌ VK API ошибка {error_code}: {error_msg}")
            
            # Частые ошибки и их решения
            error_solutions = {
                901: "Разрешите сообществу отправлять сообщения в настройках",
                902: "Пользователь должен начать диалог первым",
                7: "Проверьте токен и права бота",
                914: "Сообщение слишком длинное",
                935: "Слишком много сообщений в секунду"
            }
            
            if error_code in error_solutions:
                logger.error(f"💡 Решение: {error_solutions[error_code]}")
            
            return False
            
        logger.info(f"✅ Сообщение отправлено пользователю {user_id}")
        return True
            
    except Exception as e:
        logger.error(f"❌ Ошибка отправки сообщения: {e}")
        return False       

@app.route('/vk-callback', methods=['POST'])
@rate_limit
def vk_callback():
    """Обработчик Callback API для VK (исправленная версия)"""
    try:
        data = request.json
        logger.info(f"VK Callback received: {data.get('type', 'unknown')}")
        
        # Подтверждение для Callback API
        if data['type'] == 'confirmation':
            confirmation_code = os.environ.get('VK_CONFIRMATION_CODE', '')
            if not confirmation_code:
                logger.error("❌ VK_CONFIRMATION_CODE not set in environment")
                return 'confirmation_error'
            logger.info(f"Returning confirmation code: {confirmation_code}")
            return confirmation_code
        
        # Обработка новых сообщений
        if data['type'] == 'message_new':
            message = data['object']['message']
            user_id = message['from_id']
            text = message['text'].lower()
            
            logger.info(f"VK Bot: User {user_id} sent: '{text}'")
            
            # Проверяем payload для кнопок
            payload = message.get('payload')
            if payload:
                try:
                    payload_data = json.loads(payload)
                    command = payload_data.get('command', '')
                    if command:
                        text = command
                        logger.info(f"Button command detected: {command}")
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid payload JSON: {payload}, error: {e}")
            
            # Обработка команд
            if text in ['/start', 'start', 'начать']:
                welcome_message = """👋 Привет! Я бот PhishGuard!

🛡️ Я помогаю обнаруживать фишинговые ссылки в ВКонтакте.

Нажмите кнопки ниже для управления:"""
                success = send_vk_message(user_id, welcome_message, get_main_keyboard())
                logger.info(f"Start command sent: {success}")
                
            elif text in ['help', '/help']:
                help_message = """🛡️ **PhishGuard - защита от фишинга**

Как это работает:
1. Установите расширение в браузере
2. Расширение автоматически проверяет ссылки в ВК
3. При обнаружении фишинга вы получите уведомление

Команды:
• Статистика - просмотр статистики проверок
• Все ссылки - история проверенных ссылок
• Опасные ссылки - список обнаруженных угроз
• Проверить ссылку - ручная проверка ссылки

Безопасность: Все проверки защищены HMAC-шифрованием."""
                send_vk_message(user_id, help_message, get_main_keyboard())
                
            elif text in ['stats', '/stats']:
                formatted_time = stats['last_check'] if stats['last_check'] else 'еще не было'
                stats_message = f"""📊 **Статистика PhishGuard**

✅ Всего проверок: {stats['total_checks']}
🚫 Обнаружено угроз: {stats['malicious_count']}
👥 Уникальных пользователей: {len(stats['users'])}
⏰ Последняя проверка: {formatted_time}

📈 Бот активно защищает пользователей ВК!"""
                send_vk_message(user_id, stats_message, get_main_keyboard())
                
            elif text in ['all_links', 'links']:
                if stats['link_history']:
                    recent_links = stats['link_history'][-10:]  # Последние 10 ссылок
                    links_message = "🔗 **Последние проверенные ссылки:**\n\n"
                    for link in recent_links:
                        status = "🚫 ФИШИНГ" if link.get('is_malicious') else "✅ Безопасно"
                        links_message += f"{status}: {link.get('domain', 'unknown')}\n"
                else:
                    links_message = "📭 Пока нет проверенных ссылок."
                send_vk_message(user_id, links_message, get_main_keyboard())
                
            elif text in ['malicious_links', 'danger']:
                if stats['malicious_links']:
                    malicious_message = "🚫 **Обнаруженные фишинговые ссылки:**\n\n"
                    for link in stats['malicious_links'][-5:]:  # Последние 5 фишинговых
                        malicious_message += f"• {link.get('domain', 'unknown')}\n"
                else:
                    malicious_message = "✅ Пока не обнаружено фишинговых ссылок!"
                send_vk_message(user_id, malicious_message, get_main_keyboard())
                
            elif text in ['check', 'проверить']:
                check_message = """🔍 **Проверить ссылку**

Отправьте мне ссылку для проверки, например:
`https://example.com`

Или используйте расширение PhishGuard для автоматической проверки всех ссылок в ВК."""
                send_vk_message(user_id, check_message, get_main_keyboard())
                
            else:
                # Если просто текст (не команда), предлагаем помощь
                if not payload:  # Если это не нажатие кнопки
                    unknown_message = f"🤖 Я не понял команду '{text}'\n\nИспользуйте кнопки ниже или напишите /help для справки."
                    send_vk_message(user_id, unknown_message, get_main_keyboard())
        
        return 'ok'
        
    except Exception as e:
        logger.error(f"Callback error: {e}")
        import traceback
        traceback.print_exc()
        return 'ok'

@app.route('/send-welcome/<int:user_id>', methods=['GET'])
def send_welcome(user_id):
    """Принудительно отправляет приветственное сообщение"""
    try:
        welcome_message = """👋 Привет! Это PhishGuard бот!

Я отправляю уведомления об опасных ссылках в ВК.

⚠️ Если вы получили это сообщение - значит бот работает!
⚠️ Если кнопки не отображаются - проверьте настройки клавиатуры.

📌 **Для настройки расширения:**
1. Установите расширение из магазина
2. Авторизуйтесь в ВК
3. Расширение начнет работу автоматически

👇 Проверьте, видны ли кнопки:"""
        
        success = send_vk_message(user_id, welcome_message, get_main_keyboard())
        
        if success:
            return jsonify({
                "status": "success",
                "message": f"Welcome message sent to {user_id}",
                "keyboard_sent": True,
                "timestamp": datetime.now().isoformat()
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Failed to send welcome message"
            }), 500
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/bot-status', methods=['GET'])
def bot_status():
    """Проверяет состояние VK бота"""
    try:
        return jsonify({
            "status": "running",
            "vk_token_set": bool(VK_TOKEN),
            "confirmation_code_set": bool(os.environ.get('VK_CONFIRMATION_CODE')),
            "total_users": len(stats['users']),
            "total_checks": stats['total_checks'],
            "malicious_detected": stats['malicious_count'],
            "keyboard_enabled": True,
            "server_time": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/test-sentry', methods=['GET'])
def test_sentry():
    """Тестовый endpoint для проверки Sentry"""
    
    # Проверяем доступность Sentry
    sentry_enabled = False
    try:
        # Пробуем импортировать Sentry
        import sentry_sdk
        sentry_enabled = True
    except ImportError:
        sentry_enabled = False
    
    # Тест 1: Простое сообщение
    if sentry_enabled:
        try:
            sentry_sdk.capture_message("Тестовое сообщение из /api/test-sentry", level="info")
            message_sent = True
        except:
            message_sent = False
    else:
        message_sent = False
    
    # Тест 2: Ошибка (опционально - раскомментируйте если нужно)
    # try:
    #     1 / 0  # Деление на ноль для теста
    # except Exception as e:
    #     if sentry_enabled:
    #         sentry_sdk.capture_exception(e)
    
    return jsonify({
        'status': 'success',
        'message': 'Sentry test endpoint',
        'sentry_enabled': sentry_enabled,
        'test_message_sent': message_sent,
        'server_time': datetime.now().isoformat(),
        'instructions': 'Uncomment line 1/0 to test error tracking'
    })   

@app.route('/api/debug')
def debug_info():
    """Отладочная информация"""
    import sys
    
    return jsonify({
        'python_version': sys.version,
        'flask_version': '2.3.3',
        'environment': os.environ.get('ENV', 'not set'),
        'sentry_dsn_set': bool(os.environ.get('SENTRY_DSN')),
        'server_time': datetime.now().isoformat(),
        'endpoints': [
            '/health',
            '/api/debug',
            '/api/test-error',
            '/status',
            '/metrics'
        ]
    })

# Добавьте где-то после других @app.route декораторов

@app.route('/api/test-error', methods=['GET'])
def test_error():
    """Endpoint для тестирования ошибок (должен отправляться в Sentry)"""
    try:
        # Создаем тестовую ошибку
        raise ValueError("Это тестовая ошибка для Sentry! Время: " + datetime.now().isoformat())
        
    except Exception as e:
        # Логируем в Sentry если доступен
        error_sent = False
        error_message = str(e)
        
        try:
            import sentry_sdk
            sentry_sdk.capture_exception(e)
            error_sent = True
            print(f"✅ Ошибка отправлена в Sentry: {error_message}")
        except Exception as sentry_error:
            print(f"⚠️ Не удалось отправить в Sentry: {sentry_error}")
        
        return jsonify({
            'test': 'error_endpoint',
            'error': error_message,
            'sentry_enabled': error_sent,
            'message': 'Тестовая ошибка создана' + (' и отправлена в Sentry' if error_sent else ' (Sentry не доступен)'),
            'timestamp': datetime.now().isoformat()
        }), 500

# ==================== ЗАПУСК СЕРВЕРА ====================
if __name__ == '__main__':
    print("🚀 Starting PhishGuard Server with FIXED HMAC...")
    logger.info("PhishGuard Server starting with corrected HMAC")
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)