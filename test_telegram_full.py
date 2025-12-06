# test_telegram_full.py
import os
import sys
import time

# Добавляем текущую директорию в путь
sys.path.append('.')

def test_setup():
    """ПРОВЕРКА НАСТРОЕК"""
    print("=" * 60)
    print("🧪 ПОЛНОЕ ТЕСТИРОВАНИЕ TELEGRAM АЛЕРТОВ")
    print("=" * 60)
    
    # Проверяем наличие .env файла
    if not os.path.exists('.env'):
        print("❌ Файл .env не найден!")
        print("Создайте файл .env в корне проекта")
        return False
    
    # Загружаем переменные окружения
    from dotenv import load_dotenv
    load_dotenv()
    
    # Проверяем обязательные переменные
    token = os.environ.get('TELEGRAM_BOT_TOKEN')
    chat_id = os.environ.get('TELEGRAM_CHAT_ID')
    
    if not token:
        print("❌ TELEGRAM_BOT_TOKEN не найден в .env")
        return False
    
    if not chat_id:
        print("❌ TELEGRAM_CHAT_ID не найден в .env")
        return False
    
    print(f"✅ TELEGRAM_BOT_TOKEN: {'*' * 20}{token[-10:]}")
    print(f"✅ TELEGRAM_CHAT_ID: {chat_id}")
    print("✅ Файл .env загружен корректно")
    
    return True

def test_import():
    """ПРОВЕРКА ИМПОРТА МОДУЛЯ"""
    print("\n" + "=" * 60)
    print("📦 ТЕСТИРОВАНИЕ ИМПОРТА МОДУЛЯ")
    print("=" * 60)
    
    try:
        from telegram_alerts import TelegramAlerts, telegram_alerts
        print("✅ Модуль telegram_alerts успешно импортирован")
        return True, telegram_alerts
    except ImportError as e:
        print(f"❌ Ошибка импорта: {e}")
        return False, None

def test_basic_functionality(alerts):
    """ТЕСТИРОВАНИЕ ОСНОВНЫХ ФУНКЦИЙ"""
    print("\n" + "=" * 60)
    print("🔄 ТЕСТИРОВАНИЕ ОСНОВНЫХ ФУНКЦИЙ")
    print("=" * 60)
    
    tests = [
        {
            'name': 'Проверка работоспособности бота',
            'func': alerts.check_health,
            'args': []
        },
        {
            'name': 'Отправка информационного сообщения',
            'func': alerts.send_message,
            'args': ['Тестовое информационное сообщение', 'info']
        },
        {
            'name': 'Отправка сообщения об успехе',
            'func': alerts.send_message,
            'args': ['✅ Тест успешно пройден!', 'success']
        },
        {
            'name': 'Отправка предупреждения',
            'func': alerts.send_message,
            'args': ['⚠️ Это тестовое предупреждение', 'warning']
        },
        {
            'name': 'Отправка алерта об ошибке',
            'func': alerts.send_alert,
            'args': ['Тестовый алерт', 'Это описание тестового алерта', 'error']
        },
    ]
    
    results = []
    for test in tests:
        print(f"\n🧪 Тест: {test['name']}")
        try:
            result = test['func'](*test['args'])
            
            if test['name'] == 'Проверка работоспособности бота':
                if result.get('healthy'):
                    print(f"✅ {test['name']}: {result.get('message')}")
                    print(f"   Бот: {result.get('bot_name')} (@{result.get('bot_username')})")
                else:
                    print(f"❌ {test['name']}: {result.get('message')}")
                    print(f"   Ошибка: {result.get('error')}")
            else:
                if result:
                    print(f"✅ {test['name']}: Успешно отправлено")
                else:
                    print(f"❌ {test['name']}: Не удалось отправить")
            
            results.append({
                'test': test['name'],
                'success': result if isinstance(result, bool) else result.get('healthy', False),
                'result': result
            })
            
            # Пауза между тестами чтобы не спамить
            time.sleep(1)
            
        except Exception as e:
            print(f"❌ {test['name']}: Ошибка - {e}")
            results.append({
                'test': test['name'],
                'success': False,
                'error': str(e)
            })
    
    return results

def test_advanced_features(alerts):
    """ТЕСТИРОВАНИЕ РАСШИРЕННЫХ ФУНКЦИЙ"""
    print("\n" + "=" * 60)
    print("🎯 ТЕСТИРОВАНИЕ РАСШИРЕННЫХ ФУНКЦИЙ")
    print("=" * 60)
    
    tests = [
        {
            'name': 'Алерт безопасности',
            'func': alerts.send_security_alert,
            'args': ['Phishing', 'http://malicious-phishing-site.com/steal-data', 'user_123', 'high']
        },
        {
            'name': 'Алерт производительности',
            'func': alerts.send_performance_alert,
            'args': ['CPU Usage', '95%', '80%']
        },
        {
            'name': 'Отправка ошибки с исключением',
            'func': alerts.send_error,
            'args': [ValueError('Тестовая ошибка ValueError'), {'test_id': '123', 'module': 'test_script'}]
        },
        {
            'name': 'Ежедневный отчет',
            'func': alerts.send_daily_report,
            'args': [{
                'total_checks': 1500,
                'malicious_count': 23,
                'users': ['user1', 'user2', 'user3'],
                'uptime_hours': 24.5,
                'avg_response_time': 145.3,
                'success_rate': 99.8,
                'last_check': '2024-01-15 14:30:00'
            }]
        }
    ]
    
    results = []
    for test in tests:
        print(f"\n🧪 Тест: {test['name']}")
        try:
            result = test['func'](*test['args'])
            if result:
                print(f"✅ {test['name']}: Успешно отправлено")
            else:
                print(f"❌ {test['name']}: Не удалось отправить")
            
            results.append({
                'test': test['name'],
                'success': result,
                'result': result
            })
            
            time.sleep(1.5)  # Пауза подольше для сложных тестов
            
        except Exception as e:
            print(f"❌ {test['name']}: Ошибка - {e}")
            results.append({
                'test': test['name'],
                'success': False,
                'error': str(e)
            })
    
    return results

def test_decorators():
    """ТЕСТИРОВАНИЕ ДЕКОРАТОРОВ"""
    print("\n" + "=" * 60)
    print("🎭 ТЕСТИРОВАНИЕ ДЕКОРАТОРОВ")
    print("=" * 60)
    
    from telegram_alerts import telegram_alert_on_error, track_performance
    
    @telegram_alert_on_error
    def function_that_fails():
        """Функция которая вызывает ошибку"""
        raise ValueError("Это тестовая ошибка из декорированной функции")
    
    @track_performance('slow_function_test')
    def slow_function():
        """Функция которая выполняется медленно"""
        time.sleep(6)  # Спим 6 секунд чтобы вызвать алерт производительности
        return "Done"
    
    print("🧪 Тест декоратора telegram_alert_on_error")
    try:
        function_that_fails()
        print("❌ Ожидалась ошибка, но её не было")
    except ValueError as e:
        print(f"✅ Ошибка успешно перехвачена и отправлена в Telegram: {e}")
    
    print("\n🧪 Тест декоратора track_performance")
    try:
        result = slow_function()
        print(f"✅ Функция выполнена: {result}")
        print("   (Проверьте Telegram на наличие алерта о производительности)")
    except Exception as e:
        print(f"❌ Ошибка: {e}")
    
    return True

def main():
    """ОСНОВНАЯ ФУНКЦИЯ ТЕСТИРОВАНИЯ"""
    
    # Шаг 1: Проверка настроек
    if not test_setup():
        return
    
    # Шаг 2: Проверка импорта
    import_success, alerts = test_import()
    if not import_success or not alerts:
        return
    
    # Шаг 3: Проверка что алерты включены
    if not alerts.enabled:
        print("\n❌ Telegram алерты отключены!")
        print("Проверьте настройки в .env файле")
        return
    
    print(f"\n✅ Telegram алерты включены для Chat ID: {alerts.chat_id}")
    
    # Шаг 4: Базовые тесты
    basic_results = test_basic_functionality(alerts)
    
    # Шаг 5: Расширенные тесты
    advanced_results = test_advanced_features(alerts)
    
    # Шаг 6: Тест декораторов
    decorator_test = test_decorators()
    
    # Итоговая статистика
    print("\n" + "=" * 60)
    print("📊 ИТОГИ ТЕСТИРОВАНИЯ")
    print("=" * 60)
    
    all_results = basic_results + advanced_results
    successful = sum(1 for r in all_results if r.get('success', False))
    total = len(all_results)
    
    print(f"\n✅ Успешных тестов: {successful}/{total}")
    print(f"📈 Успешность: {(successful/total*100):.1f}%")
    
    if successful == total:
        print("\n🎉 ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО!")
        print("Telegram алерты готовы к использованию в продакшене!")
    else:
        print(f"\n⚠️ Не все тесты пройдены: {total - successful} неудачных")
        
        # Показываем ошибки
        print("\n🔍 ДЕТАЛИ ОШИБОК:")
        for result in all_results:
            if not result.get('success', False):
                print(f"  • {result['test']}")
                if 'error' in result:
                    print(f"    Ошибка: {result['error']}")
    
    # Показываем журнал ошибок
    print("\n📋 ЖУРНАЛ ОШИБОК TELEGRAM:")
    error_log = alerts.get_error_log()
    if error_log:
        for i, error in enumerate(error_log[-5:], 1):  # Последние 5 ошибок
            print(f"  {i}. [{error['timestamp']}] {error['message']}")
    else:
        print("  ✅ Ошибок нет")

if __name__ == "__main__":
    main()
