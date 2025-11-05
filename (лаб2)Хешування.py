import hashlib
import os

def get_md5_hash(data):
    # Створюємо об'єкт md5
    md5_hash = hashlib.md5()
    # "Годуємо" йому дані
    md5_hash.update(data)
    # Повертаємо хеш у шістнадцятковому вигляді (hex)
    return md5_hash.hexdigest()

def hash_string():
    user_string = input("Введіть рядок для хешування: ")
    
    # Перетворюємо рядок в байти (MD5 працює з байтами)
    hash_result = get_md5_hash(user_string.encode('utf-8'))
    
    print(f"\nMD5 хеш для рядка '{user_string}':")
    print(hash_result)
    
    # Зберігаємо у файл (за вимогою лаби)
    with open("string_hash_result.txt", "w", encoding="utf-8") as f:
        f.write(f"String: {user_string}\nMD5: {hash_result}\n")
    print("Результат збережено у 'string_hash_result.txt'")

def hash_file():
    file_path = input("Введіть повний шлях до файлу: ").strip('"')
    
    if not os.path.exists(file_path):
        print("Помилка: Файл не знайдено.")
        return

    try:
        # Створюємо об'єкт хешу
        md5_hash = hashlib.md5()
        
        # Відкриваємо файл у бінарному режимі ('rb')
        with open(file_path, 'rb') as f:
            # Читаємо файл шматками (chunks), щоб не забити пам'ять
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
        
        hash_result = md5_hash.hexdigest()
        
        print(f"\nMD5 хеш для файлу '{file_path}':")
        print(hash_result)
        
        # Зберігаємо хеш у файл .md5 поруч з оригіналом
        hash_file_path = file_path + ".md5"
        with open(hash_file_path, "w", encoding="utf-8") as f:
            f.write(hash_result)
        print(f"Хеш збережено у '{hash_file_path}'")

    except Exception as e:
        print(f"Сталася помилка при читанні файлу: {e}")

def verify_file():
    file_path = input("Введіть повний шлях до файлу для перевірки: ").strip('"')
    hash_file_path = file_path + ".md5"

    # Перевіряємо, чи є обидва файли
    if not os.path.exists(file_path):
        print("Помилка: Файл для перевірки не знайдено.")
        return
    if not os.path.exists(hash_file_path):
        print(f"Помилка: Файл з хешем '{hash_file_path}' не знайдено.")
        print("Спочатку порахуйте хеш (опція 2).")
        return
        
    try:
        # 1. Читаємо збережений (очікуваний) хеш
        with open(hash_file_path, 'r', encoding="utf-8") as f:
            expected_hash = f.read().strip()
            
        # 2. Рахуємо хеш файлу заново
        md5_hash = hashlib.md5()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
        
        actual_hash = md5_hash.hexdigest()
        
        # 3. Порівнюємо
        print(f"\n--- Перевірка цілісності ---")
        print(f"Очікуваний хеш (з файлу .md5): {expected_hash}")
        print(f"Порахований хеш (актуальний):   {actual_hash}")
        
        if actual_hash == expected_hash:
            print("\nOK: Цілісність підтверджено. Файл не змінювався.")
        else:
            print("\nУВАГА! Хеші не збігаються. Файл було змінено або пошкоджено!")

    except Exception as e:
        print(f"Сталася помилка: {e}")

def run_tests():    
    print(f"\n--- Запуск тестів (RFC 1321) ---")
    test_cases = {
        "": "d41d8cd98f00b204e9800998ecf8427e",
        "a": "0cc175b9c0f1b6a831c399e269772661",
        "abc": "900150983cd24fb0d6963f7d28e17f72",
        "message digest": "f96b697d7cb7938d525a2f31aaf161d0",
        "abcdefghijklmnopqrstuvwxyz": "c3fcd3d76192e4007dfb496cca67e13b",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789": "d174ab98d277d9f5a5611c2c9f419d9f",
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890": "57edf4a22be3c955ac49da2e2107b67a"
    }
    
    all_passed = True
    for test_string, expected_hash in test_cases.items():
        actual_hash = get_md5_hash(test_string.encode('utf-8'))
        if actual_hash == expected_hash.lower():
            print(f"PASS: H('{test_string}')")
        else:
            print(f"FAIL: H('{test_string}')")
            print(f"      Got: {actual_hash}")
            print(f"      Expected: {expected_hash.lower()}")
            all_passed = False
            
    if all_passed:
        print("--- Усі тести RFC 1321 пройдено успішно! ---")
    else:
        print("--- Деякі тести RFC 1321 провалено! ---")


#    Головне меню програми 
if __name__ == "__main__":
    while True:
        print("\n--- Програма хешування MD5 (Лабораторна 2) ---")
        print("1. Порахувати хеш рядка")
        print("2. Порахувати хеш файлу (і зберегти .md5)")
        print("3. Перевірити цілісність файлу (за .md5 файлом)")
        print("4. Запустити тести RFC 1321")
        print("0. Вихід")
        
        choice = input("Ваш вибір: ")
        
        if choice == '1':
            hash_string()
        elif choice == '2':
            hash_file()
        elif choice == '3':
            verify_file()
        elif choice == '4':
            run_tests()
        elif choice == '0':
            print("Вихід...")
            break
        else:
            print("Неправильний вибір, спробуйте ще раз.")