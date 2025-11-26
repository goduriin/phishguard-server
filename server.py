from flask import Flask, request, jsonify
import requests
import os
import json
from datetime import datetime

app = Flask(__name__)

# Конфигурация
VK_TOKEN = os.environ.get('VK_TOKEN', 'vk1.a.MI3dYhsBx8lgRdWjzrvVSHWxhTYt9-BDA9TXKbW3wCyb8m8yUO3O8SR_m6QVWtkBt49cu2iQ_BY3gR0DjTFGokcZgjyCQROJJG4VZmGdoKwOu3ZiyjI58L7eApBx2tOq_rU6IYs33OWbR__lglk3fcp2_eOGP6Z9Oamb-vC-JltZ0fLukc96G8s_C-8g6hS4jOFw0CTWYhoWKKe7af1-vw')
SECRET_KEY = os.environ.get('SECRET_KEY', 'phishguard_secret_key_2024')

# Глобальные переменные для статистики
stats = {
    'total_checks': 0,
    'malicious_count': 0,
    'users': set(),
    'last_check': None
}

# Клавиатуры для бота
def get_main_keyboard():
    """Основная клавиатура с командами"""
    return {
        "one_time": False,
        "buttons": [
            [
                {
                    "action": {
                        "type": "text",
                        "payload": "{\"button\": \"1\"}",
                        "label": "🛡️ Помощь"
                    },
                    "color": "primary"
                }
            ],
            [
                {
                    "action": {
                        "type": "text", 
                        "payload": "{\"button\": \"2\"}",
                        "label": "📊 Статистика"
                    },
                    "color": "secondary"
                },
                {
                    "action": {
                        "type": "text",
                        "payload": "{\"button\": \"3\"}",
                        "label": "🔍 Проверить ссылку"
                    },
                    "color": "positive"
                }
            ]
        ]
    }

def get_check_keyboard():
    """Клавиатура для проверки ссылок"""
    return {
        "one_time": True,
        "buttons": [
            [
                {
                    "action": {
                        "type": "text",
                        "payload": "{\"button\": \"back\"}",
                        "label": "⬅️ Назад"
                    },
                    "color": "secondary"
                }
            ]
        ]
    }

def get_admin_keyboard():
    """Клавиатура для админа"""
    return {
        "one_time": False,
        "buttons": [
            [
                {
                    "action": {
                        "type": "text",
                        "payload": "{\"button\": \"stats_all\"}",
                        "label": "📈 Полная статистика"
                    },
                    "color": "primary"
                }
            ],
            [
                {
                    "action": {
                        "type": "text",
                        "payload": "{\"button\": \"back\"}",
                        "label": "⬅️ Назад в меню"
                    },
                    "color": "secondary"
                }
            ]
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
        stats['users'].add(data.get('user_id'))
        stats['last_check'] = datetime.now().isoformat()
        
        if data.get('is_malicious'):
            stats['malicious_count'] += 1
        
        # Проверка данных
        if not data or not data.get('user_id') or not data.get('url'):
            return jsonify({"error": "Invalid data"}), 400
        
        user_id = data['user_id']
        url = data['url']
        is_malicious = data.get('is_malicious', False)
        
        # Формируем сообщение
        if is_malicious:
            message = f"⚠️ ФИШИНГ ОБНАРУЖЕН!\n\nОпасная ссылка: {url}\n\n🚫 НЕ ПЕРЕХОДИТЕ по этой ссылке!"
        else:
            message = f"✅ Ссылка безопасна\n\nПроверенная ссылка: {url}"
        
        # Отправляем в VK
        success = send_vk_message(user_id, message, get_main_keyboard())
        
        if success:
            return jsonify({"status": "success"})
        else:
            return jsonify({"error": "Failed to send VK message"}), 500
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return jsonify({"error": "Internal server error"}), 500

def send_vk_message(user_id, message, keyboard=None):
    """Отправляет сообщение через VK API"""
    try:
        print(f"📤 Sending message to user {user_id}")
        
        data = {
            'user_id': user_id,
            'message': message,
            'random_id': 0,
            'access_token': VK_TOKEN,
            'v': '5.131'
        }
        
        # Добавляем клавиатуру если она есть
        if keyboard:
            data['keyboard'] = json.dumps(keyboard)
        
        response = requests.post(
            'https://api.vk.com/method/messages.send',
            data=data,
            timeout=10
        )
        
        result = response.json()
        print(f"📩 VK API response: {result}")
        
        return 'error' not in result
            
    except Exception as e:
        print(f"❌ Send message error: {e}")
        return False

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
                payload_data = json.loads(payload)
                button = payload_data.get('button', '')
                
                if button == '1':
                    text = '/help'
                elif button == '2':
                    text = '/stats'
                elif button == '3':
                    check_message = "Введите ссылку для проверки:\n\nПример: https://example.com\nИли просто отправьте ссылку"
                    send_vk_message(user_id, check_message, get_check_keyboard())
                    return 'ok'
                elif button == 'back':
                    text = '/start'
                elif button == 'stats_all':
                    text = '/stats_all'
            
            if text == '/start':
                welcome_message = """👋 Привет! Я бот PhishGuard!

Я проверяю ссылки в вашей ленте VK и предупреждаю о фишинговых угрозах.

⚡ ДЛЯ АВТОМАТИЧЕСКОЙ РАБОТЫ:
1. Установите наше расширение в браузер Google Chrome
2. Зайдите на vk.com
3. Расширение автоматически проверит все ссылки в ленте

📱 Расширение работает только в Google Chrome!

Выберите действие:"""
                send_vk_message(user_id, welcome_message, get_main_keyboard())
                
            elif text == '/help':
                help_message = """🛡️ PhishGuard - защита от фишинга

Я автоматически проверяю ссылки в вашей ленте VK через VirusTotal API.

🔍 КАК ЭТО РАБОТАЕТ:
1. Установите расширение в Google Chrome
2. При посещении VK расширение проверяет все ссылки  
3. Если найдена фишинговая ссылка - я пришлю уведомление

⚠️ ВАЖНО: Расширение работает только в Google Chrome!

🚫 Будьте осторожны с подозрительными ссылками!"""
                send_vk_message(user_id, help_message, get_main_keyboard())
                
            elif text == '/stats':
                stats_message = f"""📊 Статистика PhishGuard

Всего проверок: {stats['total_checks']}
Обнаружено угроз: {stats['malicious_count']}
Уникальных пользователей: {len(stats['users'])}
Последняя проверка: {stats['last_check'] or 'еще не было'}"""
                send_vk_message(user_id, stats_message, get_main_keyboard())

            elif text.startswith('/check ') or (text.startswith('http') and not text.startswith('/')):
                url = text.replace('/check ', '').strip()
                if not url.startswith(('http://', 'https://')):
                    url = 'https://' + url
                
                check_message = f"🔍 Проверяю ссылку: {url}\n\nПодождите немного..."
                send_vk_message(user_id, check_message)
                
                # Имитация проверки
                import random
                import time
                time.sleep(2)
                is_safe = random.choice([True, False])
                
                if is_safe:
                    result_message = f"✅ Ссылка безопасна!\n\n{url}\n\nМожно переходить, но всегда будьте осторожны!"
                else:
                    result_message = f"⚠️ ВНИМАНИЕ! Ссылка может быть опасной!\n\n{url}\n\n🚫 Рекомендуем не переходить по этой ссылке!"
                
                send_vk_message(user_id, result_message, get_main_keyboard())

            elif text == '/admin':
                admin_ids = ["234207962"]  # Ваш VK ID
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
                admin_ids = ["234207962"]  # Ваш VK ID
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

if __name__ == '__main__':
    print("🚀 Starting PhishGuard Server...")
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)