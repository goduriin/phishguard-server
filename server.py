from flask import Flask, request, jsonify
import requests
import os
from datetime import datetime

app = Flask(__name__)

# Конфигурация
VK_TOKEN = os.environ.get('VK_TOKEN', 'your_vk_token_here')
SECRET_KEY = os.environ.get('SECRET_KEY', 'your_secret_key_here')

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
        success = send_vk_message(user_id, message)
        
        if success:
            return jsonify({"status": "success"})
        else:
            return jsonify({"error": "Failed to send VK message"}), 500
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return jsonify({"error": "Internal server error"}), 500

def send_vk_message(user_id, message):
    """Отправляет сообщение через VK API"""
    try:
        print(f"📤 Sending message to user {user_id}")
        
        response = requests.post(
            'https://api.vk.com/method/messages.send',
            data={
                'user_id': user_id,
                'message': message,
                'random_id': 0,
                'access_token': VK_TOKEN,
                'v': '5.131'
            },
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
            
            if text in ['/start', '/help']:
                help_message = """👋 Я бот PhishGuard!"""
                send_vk_message(user_id, help_message)
                
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
    app.run(host='0.0.0.0', port=port, debug=True)