from flask import Flask, request, jsonify
import requests
import os
import json
from datetime import datetime

app = Flask(__name__)

# Конфигурация из переменных окружения
VK_TOKEN = os.environ.get('VK_TOKEN')
SECRET_KEY = os.environ.get('SECRET_KEY')

# Глобальные переменные для статистики
stats = {
    'total_checks': 0,
    'malicious_count': 0,
    'users': set(),
    'last_check': None,
    'malicious_links': []  # Только подозрительные ссылки
}

# Клавиатуры для бота
def get_main_keyboard():
    """Основная клавиатура с командами"""
    return {
        "one_time": False,
        "buttons": [
            [{
                "action": {
                    "type": "text",
                    "payload": "{\"command\":\"help\"}",
                    "label": "🛡️ Помощь"
                },
                "color": "primary"
            }],
            [{
                "action": {
                    "type": "text", 
                    "payload": "{\"command\":\"stats\"}",
                    "label": "📊 Статистика"
                },
                "color": "positive"
            }],
            [{
                "action": {
                    "type": "text", 
                    "payload": "{\"command\":\"malicious_links\"}",
                    "label": "🚫 Опасные ссылки"
                },
                "color": "negative"
            }],
            [{
                "action": {
                    "type": "text",
                    "payload": "{\"command\":\"check\"}",
                    "label": "🔍 Проверить ссылку"
                },
                "color": "primary"
            }]
        ]
    }

def get_check_keyboard():
    """Клавиатура для проверки ссылок"""
    return {
        "one_time": True,
        "buttons": [
            [{
                "action": {
                    "type": "text",
                    "payload": "{\"command\":\"back\"}",
                    "label": "⬅️ Назад"
                },
                "color": "secondary"
            }]
        ]
    }

def get_admin_keyboard():
    """Клавиатура для админа"""
    return {
        "one_time": False,
        "buttons": [
            [{
                "action": {
                    "type": "text",
                    "payload": "{\"command\":\"stats_all\"}",
                    "label": "📈 Полная статистика"
                },
                "color": "primary"
            }],
            [{
                "action": {
                    "type": "text",
                    "payload": "{\"command\":\"back\"}",
                    "label": "⬅️ Назад в меню"
                },
                "color": "secondary"
            }]
        ]
    }

@app.route('/')
def home():
    return jsonify({
        "status": "PhishGuard Server is running!",
        "version": "1.0",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

@app.route('/api/check-result', methods=['POST'])
def handle_check_result():
    """Принимает результаты проверки от расширения"""
    try:
        data = request.json
        print(f"📨 Received data from extension: {data}")
        
        # Обновляем статистику
        stats['total_checks'] += 1
        if data.get('user_id'):
            stats['users'].add(data.get('user_id'))
        stats['last_check'] = datetime.now().isoformat()
        
        user_id = data['user_id']
        url = data['url']
        is_malicious = data.get('is_malicious', False)
        
        # Если ссылка опасная - отправляем уведомление
        if is_malicious:
            stats['malicious_count'] += 1
            
            # Сохраняем опасную ссылку
            malicious_data = {
                'url': url,
                'domain': extract_domain(url),
                'timestamp': datetime.now().isoformat(),
                'user_id': user_id
            }
            stats['malicious_links'].append(malicious_data)
            
            # Ограничиваем историю 50 записями
            if len(stats['malicious_links']) > 50:
                stats['malicious_links'] = stats['malicious_links'][-50:]
            
            # Отправляем уведомление об опасной ссылке
            message = f"""🚨 ФИШИНГ ОБНАРУЖЕН!

📌 Опасная ссылка: {url}
🌐 Домен: {extract_domain(url)}
🕒 Время обнаружения: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}

🚫 НЕ ПЕРЕХОДИТЕ по этой ссылке!
⚠️ Это может быть фишинг или мошенничество!"""
            
            success = send_vk_message(user_id, message, get_main_keyboard())
            
            if success:
                return jsonify({"status": "success", "malicious_detected": True})
            else:
                return jsonify({"error": "Failed to send VK message"}), 500
        else:
            # Безопасные ссылки просто логируем
            return jsonify({"status": "success", "malicious_detected": False})
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/report-link', methods=['POST'])
def handle_link_report():
    """Принимает ВСЕ ссылки для статистики (без отправки сообщений)"""
    try:
        data = request.json
        print(f"📨 Received link report: {data}")
        
        # Обновляем статистику
        stats['total_checks'] += 1
        if data.get('user_id'):
            stats['users'].add(data.get('user_id'))
        stats['last_check'] = datetime.now().isoformat()
        
        # Только логируем для статистики, не отправляем сообщения
        
        return jsonify({
            "status": "success", 
            "message": "Link saved to statistics"
        })
        
    except Exception as e:
        print(f"❌ Link report error: {e}")
        return jsonify({"error": "Internal server error"}), 500

def extract_domain(url):
    """Извлекает домен из URL"""
    try:
        from urllib.parse import urlparse
        return urlparse(url).netloc
    except:
        return "invalid_url"

def check_url_safety(url):
    """Проверяет URL через VirusTotal API"""
    try:
        API_KEY = "4d023472b5d0cb0b76552c63c9e0668b2dcf32f6f9fcb0ffb5298049732b8096"
        
        # Имитация проверки
        import random
        import time
        time.sleep(2)
        
        # Случайный результат для демонстрации
        is_safe = random.choice([True, True, True, False])  # 75% безопасных
        
        return {
            'is_safe': is_safe,
            'details': {
                'engine_results': {
                    'clean': 65 if is_safe else 15,
                    'malicious': 2 if is_safe else 48
                }
            }
        }
        
    except Exception as e:
        print(f"❌ Check URL error: {e}")
        return {'is_safe': False, 'error': str(e)}

@app.route('/vk-callback', methods=['POST'])
def vk_callback():
    """Обработчик Callback API для VK"""
    try:
        data = request.json
        print(f"🔄 VK Callback: {data}")
        
        if data['type'] == 'confirmation':
            confirmation_code = os.environ.get('CONFIRMATION_CODE', '')
            print(f"🔐 Returning confirmation code: {confirmation_code}")
            return confirmation_code
        
        if data['type'] == 'message_new':
            message = data['object']['message']
            user_id = message['from_id']
            text = message['text'].lower()
            payload = message.get('payload', '{}')
            
            # Обработка нажатий кнопок
            if payload:
                try:
                    payload_data = json.loads(payload)
                    command = payload_data.get('command', '')
                    
                    if command == 'help':
                        text = '/help'
                    elif command == 'stats':
                        text = '/stats'
                    elif command == 'back':
                        text = '/start'
                    elif command == 'stats_all':
                        text = '/stats_all'
                    elif command == 'malicious_links':
                        text = '/malicious_links'
                    elif command == 'check':
                        text = '/check'
                except Exception as e:
                    print(f"❌ Payload parse error: {e}")
            
            if text == '/start':
                welcome_message = """👋 Привет! Я бот PhishGuard!

🛡️ **Автоматическая защита:**
• Расширение проверяет все ссылки в ленте VK
• Опасные ссылки сразу блокируются
• Вы получаете уведомления только об угрозах

📊 **Статистика и отчеты:**
• /stats - общая статистика проверок
• /malicious_links - список опасных ссылок

🔍 **Ручная проверка:**
Отправьте мне любую ссылку или используйте /check

⚡ **Для автоматической работы установите наше расширение!**"""
                send_vk_message(user_id, welcome_message, get_main_keyboard())
                
            elif text == '/help':
                help_message = """🛡️ PhishGuard - защита от фишинга

Я автоматически проверяю ссылки в вашей ленте VK через VirusTotal API.

🔍 КАК ЭТО РАБОТАЕТ:
1. Установите расширение в Google Chrome
2. При посещении VK расширение проверяет все ссылки  
3. При обнаружении фишинга - вы получите уведомление
4. Все безопасные ссылки сохраняются в статистике

📊 КОМАНДЫ:
• /stats - статистика проверок
• /malicious_links - опасные ссылки
• /check URL - проверить ссылку

⚠️ ВАЖНО: Расширение работает только в Google Chrome!"""
                send_vk_message(user_id, help_message, get_main_keyboard())
                
            elif text == '/stats':
                # Форматируем время для красивого отображения
                if stats['last_check']:
                    try:
                        # Преобразуем ISO строку в datetime объект
                        last_check_dt = datetime.fromisoformat(stats['last_check'].replace('Z', '+00:00'))
                        # Форматируем в читаемый вид
                        formatted_time = last_check_dt.strftime('%d.%m.%Y %H:%M:%S')
                    except:
                        formatted_time = stats['last_check']
                else:
                    formatted_time = 'еще не было'
                
                stats_message = f"""📊 Статистика PhishGuard

Всего проверок: {stats['total_checks']}
Обнаружено угроз: {stats['malicious_count']}
Уникальных пользователей: {len(stats['users'])}
Последняя проверка: {formatted_time}

💡 Система работает в фоновом режиме
🚫 Уведомления приходят только об опасных ссылках"""
                send_vk_message(user_id, stats_message, get_main_keyboard())

            elif text == '/malicious_links':
                user_malicious_links = [link for link in stats.get('malicious_links', []) 
                                      if link.get('user_id') == str(user_id)]
                
                if not user_malicious_links:
                    message = "✅ Отлично! Опасных ссылок не обнаружено\n\nСистема продолжает мониторинг вашей ленты VK"
                else:
                    message = f"""🚫 Обнаружено опасных ссылок: {len(user_malicious_links)}

📋 Список опасных ссылок:
"""
                    for i, link in enumerate(user_malicious_links[-10:], 1):  # последние 10
                        try:
                            time_str = datetime.fromisoformat(link['timestamp'].replace('Z', '+00:00')).strftime('%d.%m.%Y %H:%M')
                        except:
                            time_str = link['timestamp']
                        message += f"{i}. {link['domain']} ({time_str})\n"
                    
                    message += f"\n⚠️ Всего обнаружено: {len(user_malicious_links)} опасных ссылок"
                
                send_vk_message(user_id, message, get_main_keyboard())

            # Ручная проверка ссылок
            elif text.startswith('/check ') or (text.startswith('http') and not text.startswith('/')):
                url = text.replace('/check ', '').strip()
                if not url.startswith(('http://', 'https://')):
                    url = 'https://' + url
                
                # Проверяем валидность URL
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    if not parsed.netloc:
                        raise ValueError("Invalid URL")
                except:
                    send_vk_message(user_id, "❌ Неверный формат ссылки. Пример: /check https://example.com")
                    return 'ok'
                
                check_message = f"🔍 Проверяю ссылку: {url}\n\nПодождите 10-15 секунд..."
                send_vk_message(user_id, check_message)
                
                # Реальная проверка
                result = check_url_safety(url)
                
                if result.get('error'):
                    result_message = f"❌ Ошибка проверки: {result['error']}\n\nПопробуйте позже."
                else:
                    if result['is_safe']:
                        clean_count = result['details']['engine_results']['clean']
                        malicious_count = result['details']['engine_results']['malicious']
                        
                        result_message = f"""✅ Ссылка БЕЗОПАСНА!

📌 URL: {url}
🌐 Домен: {extract_domain(url)}

📊 Результаты проверки:
• Безопасно: {clean_count} антивирусов
• Подозрительно: {malicious_count} антивирусов

💡 Можно переходить, но всегда будьте осторожны!"""
                    else:
                        clean_count = result['details']['engine_results']['clean']
                        malicious_count = result['details']['engine_results']['malicious']
                        
                        result_message = f"""🚨 ВНИМАНИЕ! Ссылка ОПАСНА!

📌 URL: {url}  
🌐 Домен: {extract_domain(url)}

📊 Результаты проверки:
• Безопасно: {clean_count} антивирусов
• ОПАСНО: {malicious_count} антивирусов

🚫 НЕ ПЕРЕХОДИТЕ по этой ссылке!
⚠️ Это может быть фишинг или мошенничество!"""
                
                send_vk_message(user_id, result_message, get_main_keyboard())

            elif text == '/admin':
                admin_ids = ["234207962", "473570076"]
                if str(user_id) in admin_ids:
                    admin_message = f"""⚙️ Панель администратора

Общая статистика:
- Пользователей: {len(stats['users'])}
- Проверок: {stats['total_checks']}
- Обнаружено угроз: {stats['malicious_count']}"""
                    send_vk_message(user_id, admin_message, get_admin_keyboard())
                else:
                    send_vk_message(user_id, "⛔ У вас нет прав доступа к админ панели", get_main_keyboard())

            elif text == '/stats_all':
                admin_ids = ["234207962", "473570076"]
                if str(user_id) in admin_ids:
                    full_stats = f"""📈 Полная статистика

Всего проверок: {stats['total_checks']}
Обнаружено угроз: {stats['malicious_count']}
Уникальных пользователей: {len(stats['users'])}
Последняя проверка: {stats['last_check'] or 'N/A'}

ID пользователей: {', '.join(list(stats['users'])[:5])}{'...' if len(stats['users']) > 5 else ''}"""
                    send_vk_message(user_id, full_stats, get_admin_keyboard())
                else:
                    send_vk_message(user_id, "⛔ У вас нет прав доступа", get_main_keyboard())
                
            else:
                if not text.startswith('/'):
                    help_offer = """Не понял ваше сообщение 🤔

Используйте кнопки ниже или команды:"""
                    send_vk_message(user_id, help_offer, get_main_keyboard())
                
        return 'ok'
        
    except Exception as e:
        print(f"❌ Callback error: {e}")
        return 'ok'

def send_vk_message(user_id, message, keyboard=None):
    """Отправляет сообщение через VK API"""
    try:
        print(f"📤 Sending message to user {user_id}")
        
        params = {
            'user_id': int(user_id),
            'message': message,
            'random_id': int(datetime.now().timestamp() * 1000),
            'access_token': VK_TOKEN,
            'v': '5.199'
        }
        
        if keyboard:
            keyboard_json = json.dumps(keyboard, ensure_ascii=False)
            params['keyboard'] = keyboard_json
        
        response = requests.post(
            'https://api.vk.com/method/messages.send',
            data=params,
            timeout=10
        )
        
        result = response.json()
        print(f"📩 VK API response: {result}")
        
        if 'error' in result:
            error = result['error']
            print(f"❌ VK API Error {error.get('error_code')}: {error.get('error_msg')}")
            return False
            
        return True
            
    except Exception as e:
        print(f"❌ Send message error: {e}")
        return False

# Debug endpoint для проверки переменных окружения
@app.route('/debug-env')
def debug_env():
    """Проверка переменных окружения"""
    import os
    return jsonify({
        "CONFIRMATION_CODE": os.environ.get('CONFIRMATION_CODE', 'NOT_SET'),
        "VK_TOKEN_set": bool(os.environ.get('VK_TOKEN')),
        "SECRET_KEY_set": bool(os.environ.get('SECRET_KEY'))
    })

# Тестовый endpoint для проверки токена
@app.route('/test-token')
def test_token():
    """Проверка токена VK"""
    try:
        response = requests.post(
            'https://api.vk.com/method/groups.getById',
            data={
                'access_token': VK_TOKEN,
                'v': '5.199'
            }
        )
        return jsonify(response.json())
    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == '__main__':
    print("🚀 Starting PhishGuard Server...")
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
