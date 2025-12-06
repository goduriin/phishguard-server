# test_railway.py
import os
import subprocess
import time
import requests

def test_railway_local():
    """Тестирует запуск как на Railway"""
    print("=" * 60)
    print("🧪 ТЕСТИРОВАНИЕ RAILWAY ЛОКАЛЬНО")
    print("=" * 60)
    
    # Устанавливаем переменные как на Railway
    os.environ['ENV'] = 'production'
    os.environ['PORT'] = '5001'  # Другой порт чтобы не конфликтовать
    
    print("1. Запускаю Gunicorn (как на Railway)...")
    
    # Команда запуска как на Railway
    cmd = [
        "gunicorn", 
        "server:app",
        "-b", "0.0.0.0:5001",
        "--workers", "2",
        "--threads", "4",
        "--timeout", "30",
        "--access-logfile", "-",
        "--error-logfile", "-"
    ]
    
    # Запускаем в фоне
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )
    
    print("   Gunicorn запущен, жду 5 секунд...")
    time.sleep(5)
    
    print("\n2. Тестирую endpoints...")
    
    tests = [
        ("http://127.0.0.1:5001/health", "Health check"),
        ("http://127.0.0.1:5001/", "Main page"),
        ("http://127.0.0.1:5001/api/telegram/status", "Telegram status"),
    ]
    
    for url, name in tests:
        try:
            response = requests.get(url, timeout=5)
            print(f"   ✅ {name}: HTTP {response.status_code}")
            if response.status_code != 200:
                print(f"      Ошибка: {response.text[:100]}")
        except Exception as e:
            print(f"   ❌ {name}: {e}")
    
    print("\n3. Проверяю логи Gunicorn...")
    # Читаем логи
    try:
        process.terminate()
        stdout, stderr = process.communicate(timeout=5)
        
        print("   Логи Gunicorn:")
        for line in stdout.split('\n')[-5:]:
            if line:
                print(f"      {line}")
                
    except:
        pass
    
    print("\n" + "=" * 60)
    print("✅ Тест завершен! Если всё работает - можно деплоить на Railway!")
    print("=" * 60)

if __name__ == "__main__":
    test_railway_local()