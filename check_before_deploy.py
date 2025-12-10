import os
import json
import sys

print("=" * 70)
print("🚀 ПРОВЕРКА ПЕРЕД ДЕПЛОЕМ НА RAILWAY")
print("=" * 70)

# 1. Проверка requirements.txt
print("\n📦 1. ПРОВЕРКА requirements.txt:")
try:
    with open('requirements.txt', 'r') as f:
        content = f.read().lower()
    
    required_packages = [
        ('flask', True),
        ('gunicorn', True),
        ('requests', True),
        ('flask-cors', True),
        ('python-dotenv', True)
    ]
    
    all_good = True
    for package, required in required_packages:
        if package in content:
            print(f"   ✅ {package}")
        else:
            if required:
                print(f"   ❌ {package} - ОБЯЗАТЕЛЬНЫЙ пакет отсутствует!")
                all_good = False
            else:
                print(f"   ⚠️  {package} - рекомендуется добавить")
    
    if not all_good:
        print("\n   🔧 РЕКОМЕНДАЦИЯ: Добавьте в requirements.txt:")
        print("   gunicorn==21.2.0")
        print("   flask==2.3.3")
        
except FileNotFoundError:
    print("   ❌ Файл requirements.txt не найден!")
    print("   Создайте файл с зависимостями")

# 2. Проверка railway.json
print("\n🚂 2. ПРОВЕРКА railway.json:")
try:
    with open('railway.json', 'r') as f:
        config = json.load(f)
    
    # Проверяем обязательные поля
    checks = [
        ('build', 'builder', 'NIXPACKS'),
        ('deploy', 'startCommand', 'gunicorn'),
        ('deploy', 'healthcheckPath', '/health'),
    ]
    
    for section, key, expected in checks:
        if section in config and key in config[section]:
            value = config[section][key]
            if expected.lower() in str(value).lower():
                print(f"   ✅ {section}.{key}: {value[:50]}...")
            else:
                print(f"   ⚠️  {section}.{key}: {value} (ожидалось {expected})")
        else:
            print(f"   ❌ {section}.{key}: отсутствует")
            
except Exception as e:
    print(f"   ❌ Ошибка чтения railway.json: {e}")

# 3. Проверка .env переменных
print("\n🔐 3. ПРОВЕРКА ПЕРЕМЕННЫХ ОКРУЖЕНИЯ (.env):")
try:
    from dotenv import load_dotenv
    load_dotenv()
    
    required_vars = [
        ('TELEGRAM_BOT_TOKEN', True, '1234567890:ABC...'),
        ('TELEGRAM_CHAT_ID', True, 'число'),
        ('SECRET_KEY', True, 'любая_секретная_строка'),
        ('HMAC_SECRET_KEY', True, 'любая_секретная_строка'),
        ('ENV', False, 'production (рекомендуется)'),
    ]
    
    for var, required, example in required_vars:
        value = os.environ.get(var)
        if value:
            # Маскируем секретные значения
            display = value
            if any(keyword in var.lower() for keyword in ['token', 'key', 'secret']):
                if len(value) > 8:
                    display = f"{value[:4]}...{value[-4:]}"
            
            # Проверяем формат
            if var == 'TELEGRAM_BOT_TOKEN':
                if ':' in value and value.split(':')[0].isdigit():
                    print(f"   ✅ {var}: {display} (правильный формат)")
                else:
                    print(f"   ❌ {var}: неправильный формат! Должен быть 123456:ABCdef")
            elif var == 'TELEGRAM_CHAT_ID':
                if value.isdigit():
                    print(f"   ✅ {var}: {value} (число)")
                else:
                    print(f"   ❌ {var}: {value} (должно быть число!)")
            else:
                print(f"   ✅ {var}: {display}")
        else:
            status = "❌" if required else "⚠️ "
            print(f"   {status} {var}: отсутствует (пример: {example})")
            
except ImportError:
    print("   ❌ python-dotenv не установлен")
    print("   Установите: pip install python-dotenv")

# 4. Проверка структуры проекта
print("\n📁 4. ПРОВЕРКА СТРУКТУРЫ ПРОЕКТА:")
required_files = [
    ('server.py', True, 'Основной сервер'),
    ('telegram_alerts.py', True, 'Telegram модуль'),
    ('railway.json', True, 'Конфигурация Railway'),
    ('requirements.txt', True, 'Зависимости'),
    ('.env', True, 'Переменные окружения'),
    ('Procfile', False, 'Для совместимости'),
    ('runtime.txt', False, 'Версия Python'),
]

all_files_ok = True
for filename, required, description in required_files:
    if os.path.exists(filename):
        print(f"   ✅ {filename} - {description}")
    else:
        status = "❌" if required else "⚠️ "
        print(f"   {status} {filename} - {description} {'(ОТСУТСТВУЕТ!)' if required else ''}")
        if required:
            all_files_ok = False

# 5. Итоги
print("\n" + "=" * 70)
print("📊 ИТОГИ ПРОВЕРКИ:")

if all_files_ok:
    print("🎉 ВСЕ ОСНОВНЫЕ ПРОВЕРКИ ПРОЙДЕНЫ!")
    print("\n🚀 ГОТОВ К ДЕПЛОЮ НА RAILWAY!")
    print("\n📋 СЛЕДУЮЩИЕ ШАГИ:")
    print("1. Запушить код в GitHub: git push")
    print("2. Создать проект на railway.app")
    print("3. Подключить GitHub репозиторий")
    print("4. Добавить переменные окружения в Railway Dashboard")
    print("5. Railway автоматически деплоит!")
else:
    print("⚠️  ЕСТЬ ПРОБЛЕМЫ ДЛЯ ИСПРАВЛЕНИЯ!")
    print("Исправьте все ❌ перед деплоем")

print("\n💡 ПОДСКАЗКА: Railway сам установит Gunicorn на своей")
print("   Linux инфраструктуре, даже если у вас Windows!")
print("=" * 70)
