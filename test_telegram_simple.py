# test_telegram_simple.py - ПРОСТОЙ ТЕСТ
import os
import sys
from dotenv import load_dotenv

# Загружаем переменные окружения
load_dotenv()

print("=" * 60)
print("🧪 ПРОСТОЙ ТЕСТ TELEGRAM АЛЕРТОВ")
print("=" * 60)

# Проверяем переменные
token = os.environ.get('TELEGRAM_BOT_TOKEN')
chat_id = os.environ.get('TELEGRAM_CHAT_ID')

print(f"✅ TELEGRAM_BOT_TOKEN: {'*' * 20}{token[-10:] if token else 'НЕТ'}")
print(f"✅ TELEGRAM_CHAT_ID: {chat_id if chat_id else 'НЕТ'}")

# Проверяем модуль
try:
    from telegram_alerts import TelegramAlerts
    print("✅ Модуль telegram_alerts успешно импортирован")
    
    # Тестируем
    alerts = TelegramAlerts()
    
    if alerts.enabled:
        print(f"✅ Telegram алерты включены для Chat ID: {alerts.chat_id}")
        
        # Проверяем здоровье
        health = alerts.check_health()
        print(f"✅ Статус бота: {health['status']}")
        print(f"✅ Сообщение: {health['message']}")
        
        # Тестовая отправка
        print("\n📤 Отправляю тестовое сообщение...")
        success = alerts.send_message(
            "✅ Тест из Python скрипта!\nPhishGuard Telegram Alerts работают!",
            'success'
        )
        
        if success:
            print("✅ Тестовое сообщение отправлено! Проверьте Telegram.")
        else:
            print("❌ Не удалось отправить сообщение")
    else:
        print("❌ Telegram алерты отключены. Проверьте .env файл")
        
except ImportError as e:
    print(f"❌ Ошибка импорта: {e}")
    print("Убедитесь что telegram_alerts.py в той же папке")

print("\n" + "=" * 60)
print("📂 Текущая директория:", os.getcwd())
print("=" * 60)