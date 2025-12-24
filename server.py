from dotenv import load_dotenv
import os

#загрузка переменных 
env_path = '.env'
load_dotenv(env_path)

#проверка режима
IS_PRODUCTION = os.environ.get('ENV') == 'production'
print(f"🔧 Режим: {'ПРОДАКШЕН' if IS_PRODUCTION else 'РАЗРАБОТКА'}")

print("=" * 60)
print(" ЗАПУСК PHISHGUARD SERVER")
print("=" * 60)
print(f" Текущая директория: {os.getcwd()}")
print(f" Файл .env: {os.path.exists('.env')}")
print(f" TELEGRAM_BOT_TOKEN: {'*' * 20}{os.environ.get('TELEGRAM_BOT_TOKEN', '')[-10:]}")
print(f" TELEGRAM_CHAT_ID: {os.environ.get('TELEGRAM_CHAT_ID', 'НЕ НАЙДЕН')}")
print("=" * 60)

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
import os
from telegram_alerts import telegram_alerts, telegram_alert_on_error

#испорт тг
print("\n" + "=" * 50)
print("🤖 ЗАГРУЗКА TELEGRAM АЛЕРТОВ")
print("=" * 50)

try:
    # пробуем импортировать наш модуль
    from telegram_alerts import TelegramAlerts, telegram_alert_on_error
    
    # создаем экземпляр
    telegram_alerts = TelegramAlerts()
    TELEGRAM_ENABLED = telegram_alerts.enabled
    
    if TELEGRAM_ENABLED:
        print(" Telegram алерты ВКЛЮЧЕНЫ и готовы к работе!")
    else:
        print("Telegram алерты ОТКЛЮЧЕНЫ (проверьте .env файл)")
        
except ImportError as e:
    print(f" Telegram модуль не найден: {e}")
    TELEGRAM_ENABLED = False
    telegram_alerts = None
    
    def telegram_alert_on_error(func):
        return func
        
except Exception as e:
    print(f" Ошибка инициализации Telegram: {e}")
    TELEGRAM_ENABLED = False
    telegram_alerts = None
    
    def telegram_alert_on_error(func):
        return func

print("=" * 50)


app = Flask(__name__)


def send_startup_alert():
    """Отправляет уведомление о запуске сервера в Telegram"""
    if TELEGRAM_ENABLED and telegram_alerts and hasattr(telegram_alerts, 'enabled') and telegram_alerts.enabled:
        print(" Отправка уведомления о запуске в Telegram...")
        telegram_alerts._send_startup_notification()
        print(" Startup notification sent to Telegram")
    else:
        print("ℹ Telegram startup notification skipped")

# запускаем при старте сервера (не при первом запросе)
with app.app_context():
    send_startup_alert()
#корс конфигурация
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

def check_origin_allowed(origin):
    """проверяет разрешен ли origin для CORS"""
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

#настройка корс
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

#заголовки безопасности
@app.after_request
def add_security_headers(response):
    """добавляет заголовки безопасности """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    if request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    
    return response

#конфигурация
VK_TOKEN = os.environ.get('VK_TOKEN')
SECRET_KEY = os.environ.get('SECRET_KEY', 'phishguard_secret_key_2024')
HMAC_SECRET_KEY = os.environ.get('HMAC_SECRET_KEY', 'phishguard_hmac_secret_2024')
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')

#глобальные переменные для статистики
stats = {
    'total_checks': 0,
    'malicious_count': 0,
    'users': set(),
    'last_check': None,
    'malicious_links': [],
    'link_history': []
}

stats_lock = Lock() 

#хмак функции
def deep_sort_dict(obj):
    if isinstance(obj, dict):
        result = {}
        for key in sorted(obj.keys()):
            result[key] = deep_sort_dict(obj[key])
        return result
    elif isinstance(obj, list):
        return [deep_sort_dict(item) for item in obj]
    else:
        return obj

def generate_hmac_signature(data, timestamp):
    try:
        print(f"\n SERVER HMAC GENERATION:")
        print(f"  Timestamp: {timestamp}")
        print(f"  Original data keys: {list(data.keys()) if isinstance(data, dict) else 'not dict'}")
        
        if not data:
            print(" No data for HMAC")
            return None
            
        if isinstance(data, dict):
            sorted_data = deep_sort_dict(data)
            print(f"  Sorted keys: {list(sorted_data.keys())}")
        else:
            sorted_data = data
        
        data_str = json.dumps(sorted_data, separators=(',', ':'))
        print(f"  Data JSON (first 100): {data_str[:100]}...")
        print(f"  Data JSON length: {len(data_str)}")
        
        message = str(timestamp) + data_str + HMAC_SECRET_KEY
        print(f"  Message (first 100): {message[:100]}...")
        print(f"  Message length: {len(message)}")
        
        signature = hmac.new(
            HMAC_SECRET_KEY.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        print(f"  Generated signature: {signature[:50]}...")
        print(f"  Signature length: {len(signature)}")
        
        return signature
        
    except Exception as e:
        print(f" SERVER HMAC generation error: {e}")
        import traceback
        traceback.print_exc()
        return None

def verify_hmac_signature(data, signature, timestamp, max_age=600):
    try:
        print(f"\n=== HMAC VERIFICATION ===")
        print(f"  Path: {request.path}")
        print(f"  Timestamp: {timestamp}")
        
        if data and isinstance(data, dict):
            print(f"  Data keys ({len(data)}): {list(data.keys())}")
        
        print(f"  Received signature: {signature[:50]}..." if signature else "  No signature!")
        
        if not signature or not timestamp:
            print(" Missing signature or timestamp")
            return False
        
        try:
            ts = float(timestamp)
            if ts > 1000000000000:  
                ts_seconds = ts / 1000.0
                print(f"  Timestamp in ms: {ts} -> seconds: {ts_seconds}")
            else:
                ts_seconds = ts
                print(f"  Timestamp in seconds: {ts}")
        except ValueError:
            print(" Invalid timestamp format")
            return False
        
        current_time = time.time()
        time_diff = abs(current_time - ts_seconds)
        print(f"  Current server time: {current_time}")
        print(f"  Time difference: {time_diff:.1f} seconds")
        
        if time_diff > max_age:
            print(f" Request too old: {time_diff:.1f}s > {max_age}s")
            return False
        
        expected = generate_hmac_signature(data, timestamp)
        
        if not expected:
            print(" Failed to generate expected signature")
            return False
        
        print(f"  Expected signature: {expected[:50]}...")
        
        match = signature == expected
        print(f"  Signatures match: {match}")
        
        if not match:
            print(" DEBUG: Checking differences...")
            print(f"  Received length: {len(signature)}")
            print(f"  Expected length: {len(expected)}")
            
            min_len = min(len(signature), len(expected))
            for i in range(min_len):
                if signature[i] != expected[i]:
                    print(f"  First diff at position {i}: '{signature[i]}' != '{expected[i]}'")
                    print(f"  Received chunk: {signature[i:i+10]}")
                    print(f"  Expected chunk: {expected[i:i+10]}")
                    break
        
        return hmac.compare_digest(signature, expected)
        
    except Exception as e:
        print(f" HMAC verification error: {e}")
        import traceback
        traceback.print_exc()
        return False

#дебаг хмак эндпоинт 
@app.route('/api/debug-hmac', methods=['POST', 'OPTIONS'])
def debug_hmac():
    try:
        if request.method == 'OPTIONS':
            return jsonify({"status": "ok"}), 200
            
        data = request.json
        signature = request.headers.get('X-Signature')
        timestamp = request.headers.get('X-Timestamp')
        
        print(f"\n=== HMAC DEBUG ENDPOINT ===")
        print(f"Timestamp: {timestamp}")
        print(f"Signature: {signature[:50] if signature else 'None'}...")
        
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
    """декоратор для проверки HMAC"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #пропускаем OPTIONS запросы
        if request.method == 'OPTIONS':
            return f(*args, **kwargs)
            
        #пропускаем хелз чек
        if request.path in ['/health', '/']:
            return f(*args, **kwargs)
            
        try:
            signature = request.headers.get('X-Signature')
            timestamp = request.headers.get('X-Timestamp')
            
            print(f" Checking HMAC for {request.path}")
            
            #если нет хмак заголовков, проверяем старый способ
            if not signature or not timestamp:
                print("⚠️ No HMAC headers, checking legacy auth")
                client_secret = request.headers.get('X-Secret-Key')
                if client_secret and client_secret == SECRET_KEY:
                    print(" Legacy authentication successful")
                    return f(*args, **kwargs)
                return jsonify({"error": "HMAC signature required"}), 401
            
            #проверяем хмак
            if verify_hmac_signature(request.json, signature, timestamp):
                print(f" HMAC verified for {request.path}")
                return f(*args, **kwargs)
            else:
                print(f" Invalid HMAC signature for {request.path}")
                return jsonify({"error": "Invalid HMAC signature"}), 401
                
        except Exception as e:
            print(f"HMAC middleware error: {e}")
            return jsonify({"error": "Authentication error"}), 401
    
    return decorated_function

#райт лимит
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

#дедупликация фиш увед
class PhishingDeduplicator:
    def __init__(self):
        self.sent_alerts = {}  
        self.ALERT_COOLDOWN = 300  
    
    def get_url_hash(self, url):
        domain = extract_domain(url)
        return hashlib.md5(domain.encode()).hexdigest()
    
    def can_send_alert(self, url):
        url_hash = self.get_url_hash(url)
        current_time = time.time()
        
        if url_hash in self.sent_alerts:
            last_sent = self.sent_alerts[url_hash]
            if current_time - last_sent < self.ALERT_COOLDOWN:
                return False
        
        self.sent_alerts[url_hash] = current_time
        return True
    
    def cleanup_old(self):
        current_time = time.time()
        old_keys = [k for k, v in self.sent_alerts.items() 
                   if current_time - v > 3600]  
        for key in old_keys:
            del self.sent_alerts[key]

phishing_dedup = PhishingDeduplicator()

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

#логирование
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

#энпоинты
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
    try:
        data = request.json
        logger.info(f"Received HMAC-protected check result from user {data.get('user_id', 'unknown')}")
        
        url = data.get('final_url', data.get('url', ''))
        
        if data.get('is_malicious', False):
            phishing_dedup.cleanup_old()
            
            if not phishing_dedup.can_send_alert(url):
                logger.info(f"⏭ Duplicate phishing alert skipped for {extract_domain(url)}")
                return jsonify({
                    "status": "success", 
                    "malicious_detected": True,
                    "notification_sent": False,
                    "reason": "duplicate_cooldown"
                })
        if data.get('is_malicious', False) and TELEGRAM_ENABLED and telegram_alerts.enabled:
            telegram_alerts.send_security_alert(
                'Фишинг',
                data.get('url', 'Unknown URL'),
                data.get('user_id', 'Unknown user'),
                'critical'
            )

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
            
            # формируем сообщение
            original_url = data.get('original_url', url)
            final_url = data.get('final_url', url)
            is_vk_redirect = data.get('is_vk_redirect', False)
            
            if is_vk_redirect:
                message = f""" ФИШИНГ ОБНАРУЖЕН!

 ВНИМАНИЕ: Ссылка была замаскирована под VK!

 Маскированная ссылка: {original_url}
 Настоящая ссылка: {final_url}
 Домен: {extract_domain(final_url)}
 Время обнаружения: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}

 НЕ ПЕРЕХОДИТЕ по этой ссылке!
 Это фишинг, замаскированный под ссылку VK!"""
            else:
                message = f""" ФИШИНГ ОБНАРУЖЕН!

 Опасная ссылка: {url}
 Домен: {extract_domain(url)}
 Время обнаружения: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}

 НЕ ПЕРЕХОДИТЕ по этой ссылке!
 Это может быть фишинг или мошенничество!"""
            
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
    """Принимает отчеты о ссылках (с хмак)"""
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        logger.info(f"Received HMAC-protected link report from user {data.get('user_id', 'unknown')}")
    
        #обновляем статистику
        with stats_lock:  
            stats['total_checks'] += 1
            if data.get('user_id'):
                stats['users'].add(data.get('user_id'))
            stats['last_check'] = datetime.now().isoformat()
            
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
        
        is_malicious = link_data['is_malicious']
        domain = link_data['domain']
        
        #логируем тип ссылки
        if link_data.get('is_vk_redirect'):
            link_type = "VK маскированная"
        elif domain and ('vk.com' in domain or 'vk.' in domain):
            link_type = "VK внутренняя"
        else:
            link_type = "Внешняя"
            
        logger.info(f"Saved {link_type} link: {domain}")
        
        #простая проверка дубликатов
        if is_malicious:
            #поиск похожих фиш ссылок в послед час
            one_hour_ago = datetime.now().timestamp() - 3600
            with stats_lock:
                recent_phishing = [
                    link for link in stats['link_history'][-50:]
                    if link.get('is_malicious') 
                    and datetime.fromisoformat(link['timestamp'].replace('Z', '+00:00')).timestamp() > one_hour_ago
                ]
            
            if len(recent_phishing) > 10:  #если много фишинга за час
                logger.info(f" Много фишинга: {len(recent_phishing)} за час")
        
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
    """Клавиатура для VK бота"""
    return {
        "one_time": False,
        "buttons": [
            [
                {
                    "action": {
                        "type": "text",
                        "payload": '{"command":"help"}',
                        "label": "🛡️ Помощь"
                    },
                    "color": "primary"
                }
            ],
            [
                {
                    "action": {
                        "type": "text",
                        "payload": '{"command":"stats"}',
                        "label": "📊 Статистика"
                    },
                    "color": "positive"
                }
            ],
            [
                {
                    "action": {
                        "type": "text",
                        "payload": '{"command":"check_url"}',
                        "label": "🔍 Проверить URL"
                    },
                    "color": "secondary"
                }
            ],
            [
                {
                    "action": {
                        "type": "text",
                        "payload": '{"command":"malicious_links"}',
                        "label": "🚫 Опасные ссылки"
                    },
                    "color": "negative"
                }
            ]
        ]
    }

@telegram_alert_on_error  
def send_vk_message(user_id, message, keyboard=None):
    """Отправляет сообщение через VK API """
    try:
        logger.info(f" Отправка сообщения пользователю {user_id}")
        logger.info(f" Отправка сообщения пользователю {user_id}")
        
        params = {
            'user_id': int(user_id),
            'message': message,
            'random_id': int(datetime.now().timestamp() * 1000),
            'access_token': VK_TOKEN,
            'v': '5.199'
        }
        
        if keyboard:
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
            
            logger.error(f" VK API ошибка {error_code}: {error_msg}")
            
            # Частые ошибки и их решения
            error_solutions = {
                901: "Разрешите сообществу отправлять сообщения в настройках",
                902: "Пользователь должен начать диалог первым",
                7: "Проверьте токен и права бота",
                914: "Сообщение слишком длинное",
                935: "Слишком много сообщений в секунду"
            }
            
            if error_code in error_solutions:
                logger.error(f" Решение: {error_solutions[error_code]}")
            
            if TELEGRAM_ENABLED and telegram_alerts.enabled:
                telegram_alerts.send_alert(
                    " Ошибка отправки VK сообщения",
                    f"Пользователь: {user_id}\nКод ошибки: {error_code}",
                    'error',
                    {'error_msg': error_msg, 'solution': error_solutions.get(error_code, 'Unknown')}
                )
            return False
            
        logger.info(f" Сообщение отправлено пользователю {user_id}")
        if TELEGRAM_ENABLED and telegram_alerts.enabled:
            telegram_alerts.send_alert(
                " VK сообщение отправлено",
                f"Пользователь: {user_id}\nДлина сообщения: {len(message)} символов",
                'success'
            )
        return True
    
            
    except Exception as e:
        logger.error(f" Ошибка отправки сообщения: {e}")
        return False       

@app.route('/vk-callback', methods=['POST'])
@rate_limit
def vk_callback():
    try:
        data = request.json
        logger.info(f"VK Callback received: {data.get('type', 'unknown')}")
        
        if data['type'] == 'confirmation':
            confirmation_code = os.environ.get('VK_CONFIRMATION_CODE', '')
            if not confirmation_code:
                logger.error(" VK_CONFIRMATION_CODE not set in environment")
                return 'confirmation_error'
            logger.info(f"Returning confirmation code: {confirmation_code}")
            return confirmation_code
        
        if data['type'] == 'message_new':
            message = data['object']['message']
            user_id = message['from_id']
            text = message['text'].lower()
            
            logger.info(f"VK Bot: User {user_id} sent: '{text}'")
            
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
            
            if text in ['/start', 'start', 'начать']:
                welcome_message = """ Привет! Я бот PhishGuard!

 Я помогаю обнаруживать фишинговые ссылки в ВКонтакте.

Нажмите кнопки ниже для управления:"""
                success = send_vk_message(user_id, welcome_message, get_main_keyboard())
                logger.info(f"Start command sent: {success}")
                
            elif text in ['help', '/help']:
                help_message = """ **PhishGuard - защита от фишинга**

Как это работает:
1. Установите расширение в браузере
2. Расширение автоматически проверяет ссылки в ВК
3. При обнаружении фишинга вы получите уведомление

Команды:
• Статистика - просмотр статистики проверок
• Все ссылки - история проверенных ссылок
•  Проверить URL - ручная проверка ссылки
• Опасные ссылки - список обнаруженных угроз

Безопасность: Все проверки защищены HMAC-шифрованием."""
                send_vk_message(user_id, help_message, get_main_keyboard())
                
            elif text in ['stats', '/stats']:
                formatted_time = stats['last_check'] if stats['last_check'] else 'еще не было'
                stats_message = f""" **Статистика PhishGuard**

 Всего проверок: {stats['total_checks']}
 Обнаружено угроз: {stats['malicious_count']}
 Уникальных пользователей: {len(stats['users'])}
 Последняя проверка: {formatted_time}

 Бот активно защищает пользователей ВК!"""
                send_vk_message(user_id, stats_message, get_main_keyboard())

            elif text in ['check_url', 'check', 'проверить']:
                check_message = """Проверить URL
Отправьте мне ссылку для проверки, например:
`https://example.com`

Я проверю её через VirusTotal и сообщу результат.

📌 Формат: просто отправьте ссылку в следующем сообщении."""
                send_vk_message(user_id, check_message)

            elif text.startswith('http://') or text.startswith('https://'):
                #отправил URL для проверки
                url = text.strip()
                logger.info(f"User {user_id} requested URL check: {url}")

                #проверяем URL
                check_message = f""" Проверяю ссылку...

 URL: {url[:50]}...
 Домен: {extract_domain(url)}

Пожалуйста, подождите 5-10 секунд..."""
                send_vk_message(user_id, check_message)

                try:
                    #проверка через VirusTotal
                    vt_result = check_virustotal(url)
                    
                    if vt_result.get('error'):
                        result_message = f""" Не удалось проверить ссылку

Ошибка: {vt_result.get('message', 'Unknown error')}

Попробуйте позже или проверьте правильность URL."""  
                    else:
                        is_malicious = vt_result.get('malicious_count', 0) > 0     

                        if is_malicious:
                            result_message = f""" ФИШИНГ ОБНАРУЖЕН!

 URL: {url[:80]}...
 Домен: {extract_domain(url)}

 Результаты VirusTotal:
• Вредоносных: {vt_result.get('malicious_count', 0)}
• Подозрительных: {vt_result.get('suspicious_count', 0)}
• Безопасных: {vt_result.get('harmless_count', 0)}
• Неопределенных: {vt_result.get('undetected_count', 0)}

НЕ ПЕРЕХОДИТЕ по этой ссылке!
Это может быть фишинг или мошенничество!"""
                        else:
                            result_message = f""" URL БЕЗОПАСЕН

 URL: {url[:80]}...
 Домен: {extract_domain(url)}

 Результаты VirusTotal:
•  Вредоносных: {vt_result.get('malicious_count', 0)}
•  Подозрительных: {vt_result.get('suspicious_count', 0)}
•  Безопасных: {vt_result.get('harmless_count', 0)}
•  Неопределенных: {vt_result.get('undetected_count', 0)}

 Можно переходить по ссылке (но всегда будьте осторожны)!"""
                    
                    send_vk_message(user_id, result_message, get_main_keyboard())        
                except Exception as e:
                    logger.error(f"URL check failed: {e}")
                    error_message = f""" Ошибка проверки

Не удалось проверить ссылку.
Пожалуйста, попробуйте позже."""
                    send_vk_message(user_id, error_message, get_main_keyboard())

            elif text in ['all_links', 'links']:
                if stats['link_history']:
                    recent_links = stats['link_history'][-10:]  #последние 10 ссылок
                    links_message = " **Последние проверенные ссылки:**\n\n"
                    for link in recent_links:
                        status = " ФИШИНГ" if link.get('is_malicious') else "Безопасно"
                        links_message += f"{status}: {link.get('domain', 'unknown')}\n"
                else:
                    links_message = " Пока нет проверенных ссылок."
                send_vk_message(user_id, links_message, get_main_keyboard())
                
            elif text in ['malicious_links', 'danger']:
                if stats['malicious_links']:
                    malicious_message = " **Обнаруженные фишинговые ссылки:**\n\n"
                    for link in stats['malicious_links'][-5:]:  #последние 5 фишинговых
                        malicious_message += f"• {link.get('domain', 'unknown')}\n"
                else:
                    malicious_message = "Пока не обнаружено фишинговых ссылок!"
                send_vk_message(user_id, malicious_message, get_main_keyboard())
                
            else:
                
                if not payload:  
                    unknown_message = f" Я не понял команду '{text}'\n\nИспользуйте кнопки ниже или напишите /help для справки."
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
        welcome_message = """ Привет! Это PhishGuard бот!

Я отправляю уведомления об опасных ссылках в ВК.

 Если вы получили это сообщение - значит бот работает!
 Если кнопки не отображаются - проверьте настройки клавиатуры.

 Для настройки расширения:
1. Установите расширение из магазина
2. Авторизуйтесь в ВК
3. Расширение начнет работу автоматически

 Проверьте, видны ли кнопки:"""
        
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

@app.route('/api/debug')
def debug_info():
    """Отладочная информация"""
    import sys
    
    return jsonify({
        'python_version': sys.version,
        'flask_version': '2.3.3',
        'environment': os.environ.get('ENV', 'not set'),
        'server_time': datetime.now().isoformat(),
        'endpoints': [
            '/health',
            '/api/debug',
            '/api/test-error',
            '/status',
            '/metrics'
        ]
    })

#тг энпоинты

@app.route('/api/telegram/status', methods=['GET'])
def telegram_status():
    """Возвращает статус тг алертов"""
    try:
        health = telegram_alerts.check_health() if telegram_alerts else {'status': 'disabled'}
        error_log = telegram_alerts.get_error_log(5) if telegram_alerts else []
        
        return jsonify({
            'enabled': telegram_alerts.enabled if telegram_alerts else False,
            'health': health,
            'recent_errors': error_log,
            'config': {
                'bot_token_configured': bool(os.environ.get('TELEGRAM_BOT_TOKEN')),
                'chat_id_configured': bool(os.environ.get('TELEGRAM_CHAT_ID')),
                'max_retries': 3
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/telegram/test', methods=['POST'])
def telegram_test_endpoint():
    """Тестовый endpoint для отправки алертов"""
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        test_type = data.get('type', 'info')
        
        test_messages = {
            'info': 'Тестовое информационное сообщение от API',
            'success': ' Тестовое сообщение об успехе',
            'warning': ' Тестовое предупреждение',
            'error': ' Тестовая ошибка',
            'critical': ' Критическая тестовая ошибка'
        }
        
        message = test_messages.get(test_type, test_messages['info'])
        
        if telegram_alerts and telegram_alerts.enabled:
            success = telegram_alerts.send_message(
                f"*API Test:* {message}\n`{datetime.now().strftime('%H:%M:%S')}`",
                test_type
            )
        else:
            success = False
            
        return jsonify({
            'success': success,
            'type': test_type,
            'message': message,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

#функции вирустотал
def check_virustotal(url):
    try:
        if not VIRUSTOTAL_API_KEY:
            return {"error": True, "message": "VirusTotal API key not configured"}
        
        import base64
        
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY,
            'Accept': 'application/json'
        }
        
        response = requests.get(
            f'https://www.virustotal.com/api/v3/urls/{url_id}',
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            
            return {
                "malicious_count": stats.get('malicious', 0),
                "suspicious_count": stats.get('suspicious', 0),
                "harmless_count": stats.get('harmless', 0),
                "undetected_count": stats.get('undetected', 0),
                "total_engines": sum(stats.values()),
                "error": False
            }
        elif response.status_code == 404:
            return analyze_virustotal(url)
        else:
            return {"error": True, "message": f"VirusTotal API error: {response.status_code}"}
            
    except requests.exceptions.Timeout:
        return {"error": True, "message": "VirusTotal timeout"}
    except Exception as e:
        logger.error(f"VirusTotal check error: {e}")
        return {"error": True, "message": str(e)}

def analyze_virustotal(url):
    """Отправляет URL на анализ в VirusTotal"""
    try:
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY,
            'Accept': 'application/json'
        }
        
        # Отправляем URL на анализ
        response = requests.post(
            'https://www.virustotal.com/api/v3/urls',
            headers=headers,
            data={'url': url},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            analysis_id = data.get('data', {}).get('id')
            
            if analysis_id:
                #ждем несколько секунд и запрашиваем результат
                import time
                time.sleep(3)
                
                report_response = requests.get(
                    f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
                    headers=headers,
                    timeout=10
                )
                
                if report_response.status_code == 200:
                    report_data = report_response.json()
                    stats = report_data.get('data', {}).get('attributes', {}).get('stats', {})
                    
                    return {
                        "malicious_count": stats.get('malicious', 0),
                        "suspicious_count": stats.get('suspicious', 0),
                        "harmless_count": stats.get('harmless', 0),
                        "undetected_count": stats.get('undetected', 0),
                        "total_engines": sum(stats.values()),
                        "error": False
                    }
        
        return {"error": True, "message": "Failed to analyze URL"}
        
    except Exception as e:
        logger.error(f"VirusTotal analysis error: {e}")
        return {"error": True, "message": str(e)}

#эндпоинт для проверки юрл
@app.route('/api/check-url', methods=['POST'])
@hmac_required
@rate_limit
def check_url_endpoint():
    """Проверка URL по запросу пользователя"""
    try:
        data = request.json
        if not data or 'url' not in data:
            return jsonify({"error": "URL is required"}), 400
        
        url = data['url']
        user_id = data.get('user_id')
        
        logger.info(f"Manual URL check requested by {user_id}: {url}")
        
        #проверяем через VirusTotal
        vt_result = check_virustotal(url)
        
        if vt_result.get('error'):
            return jsonify({
                "status": "error",
                "message": "Failed to check URL",
                "details": vt_result.get('message')
            }), 500
        
        is_malicious = vt_result.get('malicious_count', 0) > 0
        
        #формируем ответ
        result = {
            "status": "success",
            "url": url,
            "domain": extract_domain(url),
            "is_malicious": is_malicious,
            "virustotal_stats": {
                "malicious": vt_result.get('malicious_count', 0),
                "suspicious": vt_result.get('suspicious_count', 0),
                "harmless": vt_result.get('harmless_count', 0),
                "undetected": vt_result.get('undetected_count', 0),
                "total_engines": vt_result.get('total_engines', 0)
            },
            "timestamp": datetime.now().isoformat(),
            "message": " URL безопасен" if not is_malicious else " ФИШИНГ ОБНАРУЖЕН"
        }
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"URL check error: {e}")
        return jsonify({"error": "Internal server error"}), 500

#хапуск сервера
def run_production():
    """Запуск в продакшен режиме (используется на Railway)"""
    print(" Режим: ПРОДАКШЕН (Gunicorn)")
    print(" Оптимизировано для работы 24/7")
    
    port = os.environ.get('PORT', '5000')
    print(f"   Порт: {port}")
    print(f"   Воркеры: 2")
    print(f"   Потоки: 4")
    print(" Сервер готов к работе")

if __name__ == '__main__':
    if IS_PRODUCTION:
        run_production()
    else:
        run_development()