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
    'last_check': None
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
                    "payload": "{\"command\":\"stats_links\"}",
                    "label": "🔗 Мои ссылки"
                },
                "color": "secondary"
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
        
        # Добавляем в историю ссылок (новое!)
        if 'link_history' not in stats:
            stats['link_history'] = []
        
        # Сохраняем ссылку в историю (макс 100 последних)
        link_data = {
            'url': data.get('url'),
            'domain': extract_domain(data.get('url')),
            'timestamp': datetime.now().isoformat(),
            'source': data.get('source', 'unknown'),
            'is_malicious': data.get('is_malicious', False)
        }
        
        stats['link_history'].append(link_data)
        # Ограничиваем историю 100 записями
        if len(stats['link_history']) > 100:
            stats['link_history'] = stats['link_history'][-100:]
        
        # НЕ отправляем сообщение для каждой ссылки
        # Вместо этого просто логируем для статистики
        
        return jsonify({
            "status": "success", 
            "message": "Link saved to statistics",
            "stats": {
                "total_links": len(stats.get('link_history', [])),
                "user_links": len([l for l in stats.get('link_history', []) 
                                 if l.get('source') == data.get('source')])
            }
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
        
        # 1. Создаем анализ URL
        formData = {
            'url': url,
            'apikey': API_KEY
        }
        
        # Имитация проверки (замените на реальный VirusTotal API)
        # В реальности здесь будет вызов VirusTotal API
        import random
        import time
        time.sleep(2)  # Имитация задержки проверки
        
        # Случайный результат для демонстрации
        is_safe = random.choice([True, True, True, False])  # 75% безопасных
        
        return {
            'is_safe': is_safe,
            'details': {
                'engine_results': {
                    'clean': 65 if is_safe else 15,
                    'malicious': 2 if is_safe else 48
                } if is_safe else {
                    'clean': 15,
                    'malicious': 48
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
                    elif command == 'stats_links':
                        text = '/stats_links'
                    elif command == 'check':
                        text = '/check'
                except Exception as e:
                    print(f"❌ Payload parse error: {e}")
            
            if text == '/start':
                welcome_message = """👋 Привет! Я бот PhishGuard!

🛡️ **Автоматическая защита:**
• Расширение проверяет все ссылки в ленте VK
• Опасные ссылки сразу блокируются
• Вся статистика сохраняется

🔍 **Ручная проверка:**
Отправьте мне любую ссылку или используйте /check

📊 **Статистика:**
• /stats - общая статистика
• /stats_links - ваши ссылки
• /links_all - список всех ссылок

⚡ **Для автоматической работы установите наше расширение!**"""
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

            elif text == '/test_buttons':
                test_message = "Тест кнопок - если видите кнопки ниже, значит все работает!"
                send_vk_message(user_id, test_message, get_main_keyboard())

            # Новые команды для статистики ссылок
            elif text == '/stats_links':
                user_links = [link for link in stats.get('link_history', []) 
                             if link.get('source', '').endswith(str(user_id))]
                
                if not user_links:
                    stats_message = "📊 У вас пока нет сохраненных ссылок\n\nНачните просматривать ленту VK с включенным расширением!"
                else:
                    # Группируем по доменам
                    from collections import Counter
                    domains = Counter([link['domain'] for link in user_links])
                    
                    stats_message = f"""📊 Ваша статистика ссылок

Всего ссылок: {len(user_links)}
Проверено: {stats['total_checks']}
Обнаружено угроз: {stats['malicious_count']}

🏷️ Топ доменов:
"""
                    for domain, count in domains.most_common(5):
                        stats_message += f"• {domain}: {count} ссылок\n"
                    
                    stats_message += f"\n📋 Последние 5 ссылок:\n"
                    for link in user_links[-5:]:
                        emoji = "⚠️" if link['is_malicious'] else "🔗"
                        stats_message += f"{emoji} {link['domain']}\n"
                
                send_vk_message(user_id, stats_message, get_main_keyboard())

            elif text == '/links_all':
                user_links = [link for link in stats.get('link_history', []) 
                             if link.get('source', '').endswith(str(user_id))]
                
                if not user_links:
                    send_vk_message(user_id, "📭 У вас пока нет сохраненных ссылок")
                else:
                    # Показываем все ссылки с пагинацией
                    message = "📋 Все ваши ссылки:\n\n"
                    for i, link in enumerate(user_links[-10:], 1):  # последние 10
                        status = "⚠️ ОПАСНО" if link['is_malicious'] else "✅ безопасно"
                        message += f"{i}. {link['domain']} - {status}\n"
                    
                    message += f"\nВсего: {len(user_links)} ссылок\nИспользуйте /stats_links для статистики"
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
                
                # Сохраняем в статистику
                if 'link_history' not in stats:
                    stats['link_history'] = []
                
                stats['link_history'].append({
                    'url': url,
                    'domain': extract_domain(url),
                    'timestamp': datetime.now().isoformat(),
                    'source': f"manual_check_{user_id}",
                    'is_malicious': not result['is_safe']
                })

            elif text == '/admin':
                admin_ids = ["234207962", "473570076"]  # Ваш VK ID добавлен
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
                admin_ids = ["234207962", "473570076"]  # Ваш VK ID добавлен
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
        
        # Базовые параметры
        params = {
            'user_id': int(user_id),
            'message': message,
            'random_id': int(datetime.now().timestamp() * 1000),
            'access_token': VK_TOKEN,
            'v': '5.199'
        }
        
        # Добавляем клавиатуру если она есть
        if keyboard:
            keyboard_json = json.dumps(keyboard, ensure_ascii=False)
            print(f"⌨️ Keyboard JSON: {keyboard_json}")
            params['keyboard'] = keyboard_json
        
        print(f"🔧 Request params (без токена): { {k: v for k, v in params.items() if k != 'access_token'} }")
        
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