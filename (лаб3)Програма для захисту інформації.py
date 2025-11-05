import os
import math
import struct
import sys


# Генератор псевдовипадкових чисел
class PRNG_Lab1:
    # Генератор псевдовипадкових чисел з Лаби 1 (Варіант 14)
    # Використовує лінійний конгруентний метод: Xn+1 = (a * Xn + c) mod m
    
    def __init__(self, seed=7):
        # Параметри з Варіанту 14 (Лаба 1)
        self.m = 8388607  # Модуль: 2^23 - 1 (просте число Мерсенна)
        self.a = 1000     # Множник: 10^3
        self.c = 377      # Приріст
        self.Xn = seed    # Початкове значення (seed)

    def _next_int(self):
        # Генерує наступне псевдовипадкове число за формулою: Xn+1 = (a * Xn + c) mod m
        self.Xn = (self.a * self.Xn + self.c) % self.m
        return self.Xn

    def generate_bytes(self, num_bytes):
        # Генерує потрібну кількість псевдовипадкових байт
        # Використовується для створення вектора ініціалізації (IV) в RC5-CBC
        generated_bytes = b''
        
        # Генеруємо числа поки не набереться потрібна кількість байт
        while len(generated_bytes) < num_bytes:
            num = self._next_int()  # Отримуємо наступне псевдовипадкове число
            # Додаємо байти (у little-endian, наприклад)
            generated_bytes += num.to_bytes(4, 'little', signed=False)
        
        # Повертаємо рівно стільки байт, скільки просили
        return generated_bytes[:num_bytes]

# КЛАС ManualMD5 - Алгоритм хешування MD5
class ManualMD5:
    # Ручна реалізація алгоритму MD5 з Лаби 2
    # MD5 створює 128-бітний (16 байт) хеш з довільних вхідних даних
    
    def __init__(self):
        # Ініціалізація буферів A, B, C, D (RFC 1321)
        self.A = 0x67452301
        self.B = 0xEFCDAB89
        self.C = 0x98BADCFE
        self.D = 0x10325476
        
        # Таблиця T[i] = floor(2^32 * abs(sin(i+1))) для i від 0 до 63
        self.T = [int(abs(math.sin(i + 1)) * 2**32) & 0xFFFFFFFF for i in range(64)]
        
        # Таблиця зсувів S для кожного з 64 раундів
        self.S = [
            7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  # Раунд 1
            5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  # Раунд 2
            4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  # Раунд 3
            6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21   # Раунд 4
        ]
        
        self.message_length = 0  # Загальна довжина повідомлення в байтах
        self.buffer = b''        # Буфер для накопичення даних

    def _left_rotate(self, x, amount):
        # Виконує циклічний зсув вліво (circular left shift) на 32-бітному числі
        # x - число для зсуву, amount - кількість бітів для зсуву
        x &= 0xFFFFFFFF  # Обрізаємо до 32 біт
        return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF

    def _process_chunk(self, chunk):
        # Обробка одного 512-бітного (64 байти) блоку даних
        # Розбиваємо 64 байти на 16 32-бітних слів (little-endian)
        X = list(struct.unpack('<16I', chunk))
        
        # Копіюємо поточні значення буферів
        hA, hB, hC, hD = self.A, self.B, self.C, self.D
        
        # Виконуємо 64 раунди обробки (4 групи по 16 раундів)
        for i in range(64):
            # Раунд 1 (0-15): F(B,C,D) = (B AND C) OR (NOT B AND D)
            if 0 <= i <= 15:
                f = (hB & hC) | ((~hB) & hD); k = i
            # Раунд 2 (16-31): G(B,C,D) = (B AND D) OR (C AND NOT D)
            elif 16 <= i <= 31:
                f = (hD & hB) | ((~hD) & hC); k = (5 * i + 1) % 16
            # Раунд 3 (32-47): H(B,C,D) = B XOR C XOR D
            elif 32 <= i <= 47:
                f = hB ^ hC ^ hD; k = (3 * i + 5) % 16
            # Раунд 4 (48-63): I(B,C,D) = C XOR (B OR NOT D)
            elif 48 <= i <= 63:
                f = hC ^ (hB | (~hD)); k = (7 * i) % 16
            
            # Основне перетворення: temp = A + f + X[k] + T[i]
            temp = (hA + f + X[k] + self.T[i]) & 0xFFFFFFFF
            # Циклічна перестановка: (A, B, C, D) = (D, B + ROL(temp, S[i]), B, C)
            (hA, hB, hC, hD) = (hD, (hB + self._left_rotate(temp, self.S[i])) & 0xFFFFFFFF, hB, hC)

        # Додаємо результати обробки до поточних буферів
        self.A = (self.A + hA) & 0xFFFFFFFF
        self.B = (self.B + hB) & 0xFFFFFFFF
        self.C = (self.C + hC) & 0xFFFFFFFF
        self.D = (self.D + hD) & 0xFFFFFFFF

    def update(self, data):
        # Додає нові дані до хешу (можна викликати багато разів)
        self.buffer += data
        self.message_length += len(data)
        
        # Обробляємо всі повні 64-байтні блоки
        while len(self.buffer) >= 64:
            self._process_chunk(self.buffer[:64])
            self.buffer = self.buffer[64:]

    def digest(self):
        # Завершує обчислення хешу і повертає 16 байт (128 біт)
        # Зберігаємо поточний стан (щоб можна було продовжити хешування)
        final_A, final_B, final_C, final_D = self.A, self.B, self.C, self.D
        final_buffer, final_length = self.buffer, self.message_length
        
        # --- Доповнення (Padding) за стандартом MD5 ---
        # Розмір повідомлення в бітах (обрізаний до 64 біт)
        original_length_bits = (final_length * 8) & 0xFFFFFFFFFFFFFFFF
        
        # Додаємо біт '1' (байт 0x80) після повідомлення
        final_buffer += b'\x80'
        
        # Додаємо нулі, щоб довжина стала 56 mod 64 (залишаємо 8 байт для довжини)
        final_buffer += b'\x00' * ((56 - (len(final_buffer) % 64)) % 64)
        
        # Додаємо довжину оригінального повідомлення (64 біти, little-endian)
        final_buffer += struct.pack('<Q', original_length_bits)
        
        # Обробляємо останні блоки після доповнення
        while len(final_buffer) >= 64:
            self._process_chunk(final_buffer[:64])
            final_buffer = final_buffer[64:]
            
        # Пакування результату: конкатенація A, B, C, D (little-endian)
        digest_bytes = struct.pack('<IIII', self.A, self.B, self.C, self.D)
        
        # Відновлюємо стан (щоб можна було продовжити хешування)
        self.A, self.B, self.C, self.D = final_A, final_B, final_C, final_D
        return digest_bytes
    
    def hexdigest(self):
        # Повертає хеш у вигляді шістнадцяткового рядка (32 символи)
        return self.digest().hex()

# Симетричний блоковий шифр RC5
class ManualRC5:
    # Ручна реалізація RC5-32/12/32 (Варіант 14)
    # w = 32 біти (розмір слова) => блок = 64 біти (2 слова)
    # r = 12 раундів шифрування
    # b = 32 байти (256 біт) - довжина ключа
    
    def __init__(self, key):
        # --- Параметри з Варіанту 14 ---
        self.w = 32       # Розмір слова в бітах (word size)
        self.r = 12       # Кількість раундів шифрування
        self.b = 32       # Довжина ключа в байтах (256 біт)
        
        # Розмір блоку в байтах: 2 * w / 8 = 2 * 32 / 8 = 8 байт (64 біти)
        self.block_size = (2 * self.w) // 8
        
        # Маска для обмеження значень до 32 біт (0xFFFFFFFF)
        self.mod_mask = 0xFFFFFFFF 
        
        # --- Магічні константи для w=32 (з специфікації RC5) ---
        # Pw = Odd((e - 2) * 2^32) де e = 2.71828... 
        self.Pw = 0xB7E15163
        # Qw = Odd((φ - 1) * 2^32) де φ = 1.61803...
        self.Qw = 0x9E3779B9
        
        # Перевірка довжини ключа
        if len(key) != self.b:
            raise ValueError(f"Довжина ключа має бути {self.b} байт, а не {len(key)}")
        
        # Створюємо масив підключів S (key schedule)
        self.S = self._key_schedule(key)

    def _left_rotate(self, val, r_bits):
        # Циклічний зсув вліво (x<<<y) для 32-бітного числа
        # Біти, що виходять зліва, повертаються справа
        r_bits %= self.w  # Обмежуємо кількість зсувів до розміру слова
        return ((val << r_bits) & self.mod_mask) | (val >> (self.w - r_bits))

    def _right_rotate(self, val, r_bits):
        # Циклічний зсув вправо (x>>>y) для 32-бітного числа
        # Біти, що виходять справа, повертаються зліва
        r_bits %= self.w  # Обмежуємо кількість зсувів до розміру слова
        return (val >> r_bits) | ((val << (self.w - r_bits)) & self.mod_mask)

    def _key_schedule(self, key):
        # Створення підключів RC5 (Розгортання ключа - Key Schedule Algorithm)
        # Перетворює 32-байтний ключ у масив з 26 підключів S[0..25]
        
        # Перетворення ключа K у масив L
        # Перетворюємо байтовий ключ у масив 32-бітних слів
        c = (self.b + 3) // 4  # Кількість слів у ключі: 32 / 4 = 8 слів
        L = [0] * c
        
        # Заповнюємо масив L з ключа (в зворотному порядку, little-endian)
        for i in range(self.b - 1, -1, -1):
            L[i // 4] = (L[i // 4] << 8) + key[i]

        # Ініціалізація масиву підключів S
        t = 2 * (self.r + 1)  # Кількість підключів: 2 * (12 + 1) = 26
        S = [0] * t
        
        # Перший підключ S[0] = Pw
        S[0] = self.Pw
        
        # Генеруємо решту підключів: S[i] = S[i-1] + Qw
        for i in range(1, t):
            S[i] = (S[i - 1] + self.Qw) & self.mod_mask

        # Змішування масивів S і L
        # Виконуємо 3 * max(c, t) = 3 * max(8, 26) = 78 ітерацій
        i = j = A = B = 0
        num_rounds = 3 * max(c, t)
        
        for s in range(num_rounds):
            # Змішуємо S[i] з накопиченими значеннями A і B
            A = S[i] = self._left_rotate((S[i] + A + B), 3)
            # Змішуємо L[j] з новими значеннями A і B
            B = L[j] = self._left_rotate((L[j] + A + B), (A + B))
            
            # Переходимо до наступних елементів (циклічно)
            i = (i + 1) % t
            j = (j + 1) % c
        
        return S  # Повертаємо масив підключів

    def _encrypt_block(self, data):
        # Шифрування одного 64-бітного (8 байт) блоку в режимі ECB
        # Вхід: 8 байт відкритого тексту
        # Вихід: 8 байт шифротексту
        
        # Розбиваємо 8 байт на два 32-бітних слова A і B (little-endian)
        A = struct.unpack('<I', data[:4])[0]  # Перші 4 байти
        B = struct.unpack('<I', data[4:8])[0]  # Другі 4 байти
        
        # Початкове додавання підключів (whitening)
        A = (A + self.S[0]) & self.mod_mask
        B = (B + self.S[1]) & self.mod_mask
        
        # Виконуємо r=12 раундів шифрування
        for i in range(1, self.r + 1):
            # A = ((A XOR B) <<< B) + S[2*i]
            A = (self._left_rotate((A ^ B), B) + self.S[2 * i]) & self.mod_mask
            # B = ((B XOR A) <<< A) + S[2*i + 1]
            B = (self._left_rotate((B ^ A), A) + self.S[2 * i + 1]) & self.mod_mask
            
        # Пакуємо два 32-бітних слова назад у 8 байт (little-endian)
        return struct.pack('<II', A, B)

    def _decrypt_block(self, data):
        # Дешифрування одного 64-бітного (8 байт) блоку в режимі ECB
        # Виконує операції шифрування у зворотному порядку
        # Вхід: 8 байт шифротексту
        # Вихід: 8 байт відкритого тексту
        
        # Розпаковуємо 8 байт у два 32-бітних слова A і B
        A = struct.unpack('<I', data[:4])[0]
        B = struct.unpack('<I', data[4:8])[0]
        
        # Виконуємо r=12 раундів дешифрування (у зворотному порядку)
        for i in range(self.r, 0, -1):
            # B = ((B - S[2*i + 1]) >>> A) XOR A
            B = self._right_rotate((B - self.S[2 * i + 1]) & self.mod_mask, A) ^ A
            # A = ((A - S[2*i]) >>> B) XOR B
            A = self._right_rotate((A - self.S[2 * i]) & self.mod_mask, B) ^ B
            
        # Віднімаємо початкові підключі (зворотне whitening)
        B = (B - self.S[1]) & self.mod_mask
        A = (A - self.S[0]) & self.mod_mask
        
        # Пакуємо назад у 8 байт
        return struct.pack('<II', A, B)

    # Функції для роботи в режимі RC5-CBC-Pad

    def _pad(self, data):
        # Доповнення даних (Padding) за схемою PKCS#5/PKCS#7
        # Завжди додається від 1 до block_size байт
        # Кожен байт доповнення містить значення довжини доповнення
        
        # Обчислюємо, скільки байт потрібно додати (від 1 до 8)
        padding_len = self.block_size - (len(data) % self.block_size)
        
        # Створюємо доповнення: усі байти = padding_len
        # Наприклад, якщо padding_len=3, то додаємо [0x03, 0x03, 0x03]
        padding = bytes([padding_len] * padding_len)
        
        return data + padding

    def _unpad(self, data):
        # Видалення доповнення після дешифрування
        # Перевіряємо коректність доповнення перед видаленням
        
        if not data:
            return b''
        
        # Читаємо останній байт - він містить довжину доповнення
        padding_len = data[-1]
        
        # Перевірка 1: довжина доповнення має бути від 1 до block_size
        if padding_len > self.block_size or padding_len == 0:
            print("Помилка: Неправильний padding. Файл пошкоджено або невірний ключ.")
            return None
        
        # Перевірка 2: всі байти доповнення мають бути однаковими
        if data[-padding_len:] != bytes([padding_len] * padding_len):
            print("Помилка: Неправильний padding. Файл пошкоджено або невірний ключ.")
            return None
        
        # Видаляємо доповнення
        return data[:-padding_len]

    def _bytes_xor(self, b1, b2):
        # Побайтовий XOR двох блоків однакової довжини
        # Використовується в режимі CBC для змішування блоків
        return bytes([x ^ y for x, y in zip(b1, b2)])

    def encrypt_file(self, in_filename, out_filename, iv):
        # Шифрування файлу в режимі RC5-CBC-Pad
        # CBC (Cipher Block Chaining) - кожен блок змішується з попереднім
        # Це забезпечує, що однакові блоки даних шифруються по-різному
        
        # Шифруємо IV і записуємо на початок файлу
        # IV (Initialization Vector) шифруємо в режимі ECB
        # Це потрібно для безпеки, щоб приховати IV
        encrypted_iv = self._encrypt_block(iv)
        
        with open(in_filename, 'rb') as f_in, open(out_filename, 'wb') as f_out:
            # Записуємо зашифрований IV як перший блок
            f_out.write(encrypted_iv)
            
            # Ініціалізуємо попередній блок як незашифрований IV
            # В CBC кожен блок XOR-иться з попереднім зашифрованим блоком
            prev_block = iv 
            
            # Шифруємо файл блок за блоком
            while True:
                # Читаємо наступний блок відкритого тексту (8 байт)
                plaintext_block = f_in.read(self.block_size)
                
                if not plaintext_block:
                    break  # Файл закінчився
                
                # --- Реалізація CBC: C[i] = E(P[i] XOR C[i-1]) ---
                # 1. XOR поточного блоку з попереднім (для CBC)
                block_to_encrypt = self._bytes_xor(plaintext_block, prev_block)
                # 2. Шифруємо результат
                encrypted_block = self._encrypt_block(block_to_encrypt)
                
                # Записуємо зашифрований блок у файл
                f_out.write(encrypted_block)
                
                # Оновлюємо попередній блок для наступної ітерації
                prev_block = encrypted_block

    def decrypt_file(self, in_filename, out_filename):
        # Дешифрування файлу в режимі RC5-CBC-Pad
        # Виконує зворотні операції до encrypt_file
        
        try:
            with open(in_filename, 'rb') as f_in, open(out_filename, 'wb') as f_out:
                # Читаємо і дешифруємо IV
                # Перший блок файлу - це зашифрований IV
                encrypted_iv = f_in.read(self.block_size)
                
                if len(encrypted_iv) < self.block_size:
                    print("Помилка: Файл занадто малий.")
                    return False
                    
                # Дешифруємо IV в режимі ECB
                iv = self._decrypt_block(encrypted_iv)
                
                # Ініціалізуємо попередній блок як IV
                prev_block = iv
                
                # Буфер для збору всіх дешифрованих даних
                decrypted_data = b''
                
                # Дешифруємо файл блок за блоком
                while True:
                    # Читаємо наступний блок шифротексту (8 байт)
                    encrypted_block = f_in.read(self.block_size)
                    
                    if not encrypted_block:
                        break  # Файл закінчився
                        
                    # --- Реалізація CBC: P[i] = D(C[i]) XOR C[i-1] ---
                    # 1. Дешифруємо поточний блок
                    decrypted_block_xor = self._decrypt_block(encrypted_block)
                    # 2. XOR з попереднім зашифрованим блоком (для CBC)
                    plaintext_block = self._bytes_xor(decrypted_block_xor, prev_block)
                    
                    # Додаємо до буфера дешифрованих даних
                    decrypted_data += plaintext_block
                    
                    # Оновлюємо попередній блок (використовуємо ЗАШИФРОВАНИЙ блок!)
                    prev_block = encrypted_block
                
                # Видаляємо доповнення (padding)
                unpadded_data = self._unpad(decrypted_data)
                
                if unpadded_data is not None:
                    # Записуємо очищені від padding дані
                    f_out.write(unpadded_data)
                    return True
                else:
                    return False  # Помилка при видаленні padding
                    
        except Exception as e:
            print(f"Сталася помилка при дешифруванні: {e}")
            return False

# ДОПОМІЖНІ ФУНКЦІЇ

def get_key_from_password(password):
    # Генерує 32-байтний ключ для RC5 з текстового пароля
    # Використовує MD5 для перетворення пароля в ключ фіксованої довжини
    # Схема: K = H(P) || H(H(P)) де H - хеш-функція MD5
    
    # Обчислюємо H(P) - хеш пароля
    # "хеш парольної фрази стає старшими 128 бітами"
    md5_1 = ManualMD5()
    md5_1.update(password.encode('utf-8'))  # Конвертуємо пароль в UTF-8
    part1_bytes = md5_1.digest()  # Отримуємо перші 16 байт (H(P))
    
    # Обчислюємо H(H(P)) - хеш від хеша
    # "а молодшими є хеш від старших 128 бітів"
    md5_2 = ManualMD5()
    md5_2.update(part1_bytes)  # Хешуємо результат першого хешування
    part2_bytes = md5_2.digest()  # Отримуємо другі 16 байт (H(H(P)))
    
    # Конкатенація двох хешів
    # K = H(P) + H(H(P)) = 16 байт + 16 байт = 32 байти (256 біт)
    return part1_bytes + part2_bytes

# ГОЛОВНА ПРОГРАМА (МЕНЮ)
def main():
    # Головний цикл програми з інтерактивним меню
    while True:
        # Виводимо меню
        print("\n--- Програма шифрування RC5 (Лабораторна 3) ---")
        print("1. Зашифрувати файл")
        print("2. Дешифрувати файл")
        print("0. Вихід")
        choice = input("Ваш вибір: ")

        # шифрування
        if choice == '1':
            # Запитуємо параметри для шифрування
            in_file = input("Введіть повний шлях до файлу для шифрування (напр. C:\\Users\\user\\test.txt): ")
            out_file = input("Введіть повний шлях для вихідного файлу (напр. C:\\Users\\user\\encrypted.rc5): ")
            password = input("Введіть пароль: ")
            
            # Перевіряємо, чи існує вхідний файл
            if not os.path.exists(in_file):
                print(f"Помилка: Файл '{in_file}' не знайдено.")
                continue

            #Генеруємо 256-бітний ключ з пароля ---
            # Використовуємо MD5 (Лаба 2) для перетворення пароля в ключ
            key = get_key_from_password(password)
            
            #Генеруємо випадковий вектор ініціалізації (IV) ---
            # Використовуємо PRNG (Лаба 1) для генерації 8 байт (64 біти)
            prng = PRNG_Lab1()
            iv = prng.generate_bytes(8)  # IV для CBC режиму
            
            #Читаємо файл і додаємо padding ---
            with open(in_file, 'rb') as f:
                data = f.read()
            
            # Створюємо об'єкт RC5 з нашим ключем
            rc5 = ManualRC5(key)
            
            # Додаємо padding (доповнення) до даних
            padded_data = rc5._pad(data)
            
            # Створюємо тимчасовий файл з доповненими даними
            # (encrypt_file читає з файлу, тому зберігаємо проміжний результат)
            temp_padded_file = in_file + ".padded"
            with open(temp_padded_file, 'wb') as f:
                f.write(padded_data)

            #Шифруємо файл в режимі RC5-CBC 
            print("Шифрування...")
            rc5.encrypt_file(temp_padded_file, out_file, iv)
            
            # Видаляємо тимчасовий файл
            os.remove(temp_padded_file)
            
            print(f"Файл '{in_file}' успішно зашифровано у '{out_file}'.")

        # дешифрування
        elif choice == '2':
            # Запитуємо параметри для дешифрування
            in_file = input("Введіть повний шлях до файлу для дешифрування (напр. C:\\Users\\user\\encrypted.rc5): ")
            out_file = input("Введіть повний шлях для вихідного файлу (напр. C:\\Users\\user\\decrypted.txt): ")
            password = input("Введіть пароль: ")

            # Перевіряємо, чи існує зашифрований файл
            if not os.path.exists(in_file):
                print(f"Помилка: Файл '{in_file}' не знайдено.")
                continue

            # ВАЖЛИВО: має бути той самий пароль, що використовувався при шифруванні
            key = get_key_from_password(password)
            
            # IV витягується з файлу автоматично (перший блок)
            print("Дешифрування...")
            rc5 = ManualRC5(key)
            success = rc5.decrypt_file(in_file, out_file)
            
            # Перевіряємо результат
            if success:
                print(f"Файл '{in_file}' успішно дешифровано у '{out_file}'.")
            else:
                print("Помилка дешифрування. Найімовірніше, ви ввели невірний пароль.")
                # Видаляємо пустий або пошкоджений вихідний файл
                if os.path.exists(out_file):
                    os.remove(out_file)

        #  РЕЖИМ 0: ВИХІД 
        elif choice == '0':
            print("До побачення!")
            break
            
        #  НЕВІРНИЙ ВИБІР 
        else:
            print("Невірний вибір. Спробуйте ще раз.")
if __name__ == "__main__":
    main()