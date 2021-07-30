import os
import hashlib
import random
import Crypto.PublicKey.RSA
import csv
from datetime import datetime

SUB_DICTIONARY = u'1234567890'


class RingSign:
    @staticmethod
    def get_sub(text, step):
        step = step % len(SUB_DICTIONARY)
        return text.translate(
            str.maketrans(SUB_DICTIONARY, SUB_DICTIONARY[step:] + SUB_DICTIONARY[:step]))

    @staticmethod
    def get_reverse_sub(text, step):
        step = step % len(SUB_DICTIONARY)
        return text.translate(
            str.maketrans(SUB_DICTIONARY[step:] + SUB_DICTIONARY[:step], SUB_DICTIONARY))

    @staticmethod
    def generate_rsa_keys():
        return Crypto.PublicKey.RSA.generate(1024, os.urandom)

    def set_keys(self):
        for i in range(0, self.n):
            buf = self.generate_rsa_keys()
            self.keys.append(buf)

    @staticmethod
    def get_rsa_encrypted_data(data, key_e, key_n):
        result = pow(data, key_e, key_n)
        return result

    @staticmethod
    def get_rsa_decrypted_data(data, keys):
        result = pow(data, keys.d, keys.n)
        return result

    def set_n(self, number_of_mans):
        self.n = number_of_mans

    def set_l(self, len_of_rand_data):
        self.l = len_of_rand_data

    def set_q(self, len_of_rand_data):
        self.q = 1 << (len_of_rand_data - 1)

    @staticmethod
    def get_hash_message(message):
        # message.encode()
        hash_message = int(hashlib.sha1(message.encode('utf-8')).hexdigest(), 16)
        return hash_message

    def export_data_signatures_to_CSV(self):
        current_time = datetime.now()
        filename = 'data_signatures_' + current_time.strftime("%d-%m-%Y--%H-%M-%S") + '.csv'
        with open(filename, 'w', newline='') as file:
            writer = csv.writer(file, dialect='excel')
            for item in self.data_signatures:
                writer.writerow(item)
        return filename

    def import_data_signatures_from_CSV(self, filename):
        self.data_signatures.clear()
        with open(filename, 'r', newline='') as file:
            reader = csv.reader(file, dialect='excel')
            for item in reader:
                self.data_signatures.append([int(element) for element in item])

    def __init__(self):
        # список ключей
        self.keys = list()
        # количество подписантов
        self.n = 0
        # максимальная длина блока случайных данных
        self.l = 0
        # максимальное значение в блоке случайных данных
        self.q = 0
        # сигнатура подписей
        self.data_signatures = list()

    def get_sign(self, message):
        # хэшированное сообщение
        hash_message = self.get_hash_message(message)
        # буфер для данных, получаемых в процессе работы
        s = list()
        for i in range(0, self.n):
            s.append(None)
        # случайное число (инициализирующее значение для кольцевой подписи)
        v = random.randint(0, self.q)
        u = v
        # основной цикл
        for i in range(0, self.n - 1):
            # блок случайных данных
            x = random.randint(0, self.q)
            encrypted_x = self.get_rsa_encrypted_data(x, self.keys[i].e, self.keys[i].n)
            u = u ^ encrypted_x
            u = int(self.get_sub(str(u), hash_message))
            s[i] = [x, u, self.keys[i].e, self.keys[i].n]
        # дополнительный блок для подписывающего абонента
        u_dec = int(self.get_reverse_sub(str(v), hash_message))
        u_dec = u_dec ^ u  # XOR для получения g(x)
        decrypted_x = self.get_rsa_decrypted_data(u_dec, self.keys[self.n - 1])
        s[self.n - 1] = [decrypted_x, v, self.keys[self.n - 1].e, self.keys[self.n - 1].n]
        # добавляем данные из буфера в список сигнатур подписей
        for item in s:
            self.data_signatures.append(item)

    def verify_sign(self, sign, message_for_check):
        # получаем из подписи сообщение
        hash_message = self.get_hash_message(message_for_check)
        # magic getting v
        number_v = len(sign) - 1
        v = sign[number_v][1]
        u = v
        # основной цикл
        for i in range(0, 2):
            x = sign[i][0]
            encrypted_x = self.get_rsa_encrypted_data(x, sign[i][2], sign[i][3])
            u = u ^ encrypted_x
            u = int(self.get_sub(str(u), hash_message))
        if u == v:
            return 1
        else:
            return -1


def main():
    print("\nANTA BAKA?! It is file for functions!\n")


if __name__ == "__main__":
    main()
