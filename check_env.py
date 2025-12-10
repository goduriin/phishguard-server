import os
from dotenv import load_dotenv

print("=" * 60)
print("🔍 ПРОВЕРКА ПЕРЕМЕННЫХ ОКРУЖЕНИЯ")
print("=" * 60)

# Показываем текущую папку
current_dir = os.getcwd()
print(f"📂 Текущая папка: {current_dir}")

# Ищем .env файл
env_files = []
for root, dirs, files in os.walk('.'):
    for file in files:
        if file == '.env':
            env_files.append(os.path.join(root, file))

print(f"📁 Найдено .env файлов: {len(env_files)}")
for env_file in env_files:
    print(f"   • {env_file}")

# Загружаем из текущей папки
print(f"\n🔧 Загружаем .env из: .env")
load_dotenv('.env')

# Проверяем переменные
variables = [
    'TELEGRAM_BOT_TOKEN',
    'TELEGRAM_CHAT_ID', 
    'SECRET_KEY',
    'HMAC_SECRET_KEY',
    'VK_TOKEN',
    'VIRUSTOTAL_API_KEY',
    'PORT'
]

print("\n📋 ПРОВЕРКА ПЕРЕМЕННЫХ:")
for var in variables:
    value = os.environ.get(var)
    if value:
        masked = value
        if 'TOKEN' in var or 'KEY' in var:
            if len(value) > 10:
                masked = f"{value[:4]}...{value[-4:]}"
        print(f"   ✅ {var}: {masked}")
    else:
        print(f"   ❌ {var}: НЕ НАЙДЕН")

# Проверяем сам .env файл
if os.path.exists('.env'):
    print(f"\n📄 СОДЕРЖИМОЕ .env файла:")
    try:
        with open('.env', 'r', encoding='utf-8') as f:
            content = f.read()
            # Маскируем токены для безопасности
            lines = content.split('\n')
            for line in lines:
                if any(keyword in line for keyword in ['TOKEN', 'KEY', 'SECRET']):
                    parts = line.split('=')
                    if len(parts) == 2:
                        key, value = parts
                        if len(value) > 8:
                            masked_value = f"{value[:4]}...{value[-4:]}"
                            print(f"   {key}={masked_value}")
                        else:
                            print(f"   {line}")
                    else:
                        print(f"   {line}")
                else:
                    print(f"   {line}")
    except Exception as e:
        print(f"   ❌ Ошибка чтения .env: {e}")
else:
    print("\n❌ Файл .env НЕ НАЙДЕН в текущей папке!")

print("=" * 60)
