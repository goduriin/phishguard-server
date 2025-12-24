import os
import requests
import json
from datetime import datetime
import threading
import time
from functools import wraps
import logging
from dotenv import load_dotenv  


load_dotenv()


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TelegramAlerts:
    def __init__(self, max_retries=3, retry_delay=2):
        
        print("=" * 50)
        print("ИНИЦИАЛИЗАЦИЯ TELEGRAM АЛЕРТОВ")
        print("=" * 50)
        
        #получаем настройки из переменных окружения
        self.bot_token = os.environ.get('TELEGRAM_BOT_TOKEN', '').strip()
        self.chat_id = os.environ.get('TELEGRAM_CHAT_ID', '').strip()
        
        print(f" Bot Token: {'*' * 20}{self.bot_token[-10:] if self.bot_token else 'НЕТ'}")
        print(f" Chat ID: {self.chat_id if self.chat_id else 'НЕТ'}")
        
        #проверяем что токен и chat_id не пустые
        if not self.bot_token:
            print(" ОШИБКА: TELEGRAM_BOT_TOKEN не найден в переменных окружения")
            print("   Проверьте .env файл")
        if not self.chat_id:
            print(" ОШИБКА: TELEGRAM_CHAT_ID не найден в переменных окружения")
            print("   Проверьте .env файл")
        
        #настройки повторных попыток
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        
        #хранилище ошибок
        self._errors = []
        self._lock = threading.Lock()
        
        #флаг включения/отключения
        self.enabled = self._validate_credentials()
        
        if self.enabled:
            print(" Telegram алерты ВКЛЮЧЕНЫ и готовы к работе!")
            # Тестируем подключение
            self._test_connection()
        else:
            print(" Telegram алерты ОТКЛЮЧЕНЫ")
        
        print("=" * 50)
    
    def _validate_credentials(self):
        """Проверяет корректность учетных данных"""
        #ароверяем что токен и chat_id не пустые
        if not self.bot_token or not self.chat_id:
            print(f" Не хватает переменных: token={bool(self.bot_token)}, chat_id={bool(self.chat_id)}")
            return False
        
        # проверяем формат токена (должен содержать :)
        if ':' not in self.bot_token:
            print(f" Неверный формат токена (должен быть вида 123456:ABCdef)")
            return False
        
        # проверяем что chat_id - число
        try:
            int(self.chat_id)
        except ValueError:
            print(f" Chat ID должен быть числом: {self.chat_id}")
            return False
        
        return True
    
    def _test_connection(self):
        try:
            print(" Тестирую подключение к Telegram API...")
            url = f"https://api.telegram.org/bot{self.bot_token}/getMe"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    bot_info = data['result']
                    print(f" Бот подключен: {bot_info.get('first_name')} (@{bot_info.get('username')})")
                    return True
                else:
                    print(f" Telegram API вернул ошибку: {data.get('description')}")
            else:
                print(f" HTTP ошибка: {response.status_code}")
                
        except Exception as e:
            print(f"Ошибка подключения: {e}")
        
        return False
    
    def _send_telegram_request(self, method, payload):
        if not self.enabled:
            return False, {'error': 'Telegram alerts disabled'}
        
        url = f"https://api.telegram.org/bot{self.bot_token}/{method}"
        
        for attempt in range(self.max_retries):
            try:
                logger.debug(f" Отправка запроса к Telegram API (попытка {attempt + 1}/{self.max_retries})")
                
                response = requests.post(
                    url,
                    json=payload,
                    timeout=15,
                    headers={'Content-Type': 'application/json'}
                )
                
                if response.status_code != 200:
                    error_msg = f"HTTP {response.status_code}: {response.text[:100]}"
                    self._log_error(f"Telegram API error: {error_msg}")
                    
                    if attempt == self.max_retries - 1:
                        return False, {'error': error_msg}
                    
                    time.sleep(self.retry_delay)
                    continue
                
                result = response.json()
                
                if not result.get('ok'):
                    error_desc = result.get('description', 'Unknown error')
                    self._log_error(f"Telegram API returned error: {error_desc}")
                    
                    if attempt == self.max_retries - 1:
                        return False, result
                    
                    time.sleep(self.retry_delay)
                    continue
                
                logger.debug(" Запрос к Telegram API успешен")
                return True, result
                
            except requests.exceptions.Timeout:
                self._log_error(f"Timeout при попытке {attempt + 1}")
                if attempt == self.max_retries - 1:
                    return False, {'error': 'Timeout после всех попыток'}
                time.sleep(self.retry_delay)
                
            except requests.exceptions.ConnectionError:
                self._log_error(f"Connection error при попытке {attempt + 1}")
                if attempt == self.max_retries - 1:
                    return False, {'error': 'Connection error после всех попыток'}
                time.sleep(self.retry_delay)
                
            except Exception as e:
                self._log_error(f"Неожиданная ошибка: {str(e)}")
                if attempt == self.max_retries - 1:
                    return False, {'error': f'Unexpected error: {str(e)}'}
                time.sleep(self.retry_delay)
        
        return False, {'error': 'Все попытки исчерпаны'}
    
    def _log_error(self, message):
        """ЛОГИРУЕТ ОШИБКУ В ПАМЯТИ"""
        error_entry = {
            'timestamp': datetime.now().isoformat(),
            'message': message
        }
        
        with self._lock:
            self._errors.append(error_entry)
            if len(self._errors) > 20:
                self._errors = self._errors[-20:]
        
        logger.error(f"Telegram Alert Error: {message}")
    
    def _send_startup_notification(self):
        """ОТПРАВЛЯЕТ УВЕДОМЛЕНИЕ О ЗАПУСКЕ СЕРВЕРА"""
        print(" Отправляю уведомление о запуске сервера...")
        
        startup_message = f""" PhishGuard Server Started Successfully!

Server Info:
• Environment: `{os.environ.get('ENV', 'development')}`
• Start Time: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`
• Port: `{os.environ.get('PORT', '5000')}`

*Features Active:*
 Telegram Alerts
 HMAC Authentication
 Rate Limiting
 Security Headers

_Это автоматическое сообщение при запуске сервера._"""
        
        success = self.send_message(startup_message, 'success')
        
        if success:
            print(" Уведомление о запуске отправлено в Telegram!")
        else:
            print("❌ Не удалось отправить уведомление о запуске")
    
    def send_message(self, text, level='info', parse_mode='Markdown'):
        """ОТПРАВЛЯЕТ ПРОСТОЕ СООБЩЕНИЕ В TELEGRAM"""
        if not self.enabled:
            logger.debug("Telegram alerts disabled, skipping message")
            return True
        
        emoji_map = {
            'critical': '',
            'error': '',
            'warning': '',
            'info': '',
            'success': '',
            'debug': ''
        }
        
        emoji = emoji_map.get(level.lower(), '')
        formatted_text = f"{emoji} {text}"
        
        if len(formatted_text) > 4000:
            logger.warning(f"Сообщение слишком длинное ({len(formatted_text)} chars), обрезаем")
            formatted_text = formatted_text[:3997] + "..."
        
        payload = {
            'chat_id': self.chat_id,
            'text': formatted_text,
            'parse_mode': parse_mode,
            'disable_web_page_preview': True,
            'disable_notification': (level in ['info', 'debug'])
        }
        
        success, response = self._send_telegram_request('sendMessage', payload)
        
        if success:
            logger.info(f" Telegram сообщение отправлено (уровень: {level})")
            return True
        else:
            logger.error(f" Не удалось отправить Telegram сообщение: {response.get('error', 'Unknown')}")
            return False
    
    def send_alert(self, title, description, level='warning', details=None):
        """ОТПРАВЛЯЕТ СТРУКТУРИРОВАННЫЙ АЛЕРТ"""
        alert_text = f"""*{title}*

{description}

*Level:* `{level.upper()}`
*Time:* `{datetime.now().strftime('%H:%M:%S')}`
*Date:* `{datetime.now().strftime('%Y-%m-%d')}`"""
        
        if details and isinstance(details, dict):
            details_text = "\n*Details:*\n"
            for key, value in details.items():
                value_str = str(value)
                if len(value_str) > 100:
                    value_str = value_str[:97] + "..."
                details_text += f"• *{key}:* `{value_str}`\n"
            alert_text += details_text
        
        return self.send_message(alert_text, level)
    
    def send_error(self, exception, context=None):
        """ОТПРАВЛЯЕТ АЛЕРТ ОБ ОШИБКЕ"""
        error_title = " Server Error Detected"
        
        error_description = f"""*Error Type:* `{type(exception).__name__}`
*Error Message:* `{str(exception)}`"""
        
        import traceback
        tb_text = traceback.format_exc()
        if len(tb_text) > 200:
            tb_text = "..." + tb_text[-197:]
        
        error_details = {
            'exception_type': type(exception).__name__,
            'error_message': str(exception)[:100],
            'traceback_preview': tb_text,
            'timestamp': datetime.now().isoformat()
        }
        
        if context:
            error_details.update(context)
        
        return self.send_alert(error_title, error_description, 'critical', error_details)
    
    def send_security_alert(self, threat_type, url, user_id, severity='high'):
        """ОТПРАВЛЯЕТ АЛЕРТ ОБ УГРОЗЕ БЕЗОПАСНОСТИ"""
        severity_emoji = {
            'low': '',
            'medium': '', 
            'high': '',
            'critical': ''
        }
        
        emoji = severity_emoji.get(severity, '')
        alert_title = f"{emoji} Security Threat: {threat_type}"
        
        display_url = url
        if len(url) > 50:
            display_url = url[:47] + "..."
        
        alert_description = f"""*Threat Detected:* `{threat_type}`
*Severity:* `{severity.upper()}`
*Action:* `BLOCKED` 

Threat has been automatically blocked by PhishGuard system."""
        
        details = {
            'url': display_url,
            'user_id': user_id,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        }
        
        return self.send_alert(alert_title, alert_description, 'critical', details)
    
    def check_health(self):
        """ПРОВЕРЯЕТ РАБОТОСПОСОБНОСТЬ TELEGRAM БОТА"""
        if not self.enabled:
            return {
                'status': 'disabled',
                'healthy': True,
                'message': 'Telegram alerts are disabled'
            }
        
        try:
            url = f"https://api.telegram.org/bot{self.bot_token}/getMe"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    return {
                        'status': 'healthy',
                        'healthy': True,
                        'bot_name': data['result'].get('first_name'),
                        'bot_username': data['result'].get('username'),
                        'message': 'Bot is responding correctly'
                    }
                else:
                    return {
                        'status': 'unhealthy',
                        'healthy': False,
                        'error': data.get('description', 'Unknown error'),
                        'message': 'Bot API returned error'
                    }
            else:
                return {
                    'status': 'unhealthy',
                    'healthy': False,
                    'error': f'HTTP {response.status_code}',
                    'message': 'Failed to reach Telegram API'
                }
                
        except requests.exceptions.Timeout:
            return {
                'status': 'unhealthy',
                'healthy': False,
                'error': 'Timeout',
                'message': 'Telegram API timeout'
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'healthy': False,
                'error': str(e),
                'message': 'Unexpected error checking bot health'
            }
    
    def get_error_log(self, limit=10):
        """ВОЗВРАЩАЕТ ЖУРНАЛ ОШИБОК"""
        with self._lock:
            return self._errors[-limit:] if self._errors else []

#декоратор для отслеж функций
def telegram_alert_on_error(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            return result
            
        except Exception as e:
            # экземпляр для отправки ошибки
            try:
                alerts = TelegramAlerts()
                if alerts.enabled:
                    context = {
                        'function': func.__name__,
                        'module': func.__module__,
                        'timestamp': datetime.now().isoformat()
                    }
                    alerts.send_error(e, context)
            except:
                pass  
            
            raise
    
    return wrapper

# глоб экземпляр при импорте
try:
    telegram_alerts = TelegramAlerts()
    print(f" Глобальный экземпляр telegram_alerts создан: enabled={telegram_alerts.enabled}")
except Exception as e:
    print(f" Ошибка создания глобального экземпляра: {e}")
    telegram_alerts = None

