import platform
import os
import sys
import socket
import uuid
import subprocess
import re
from datetime import datetime


def get_system_info():
    """Получение информации о системе"""
    info = {}

    # Операционная система
    info['Операционная система'] = platform.system()

    # Версия ОС
    info['Версия ОС'] = platform.release()

    # Тип системы (32/64 бита)
    info['Тип системы (32/64 бит)'] = f"{platform.architecture()[0]} ({platform.machine()})"

    # Процессор
    info['Процессор'] = platform.processor()

    # Объём ОЗУ
    try:
        if sys.platform == "win32":
            # Для Windows
            mem_cmd = subprocess.check_output('wmic OS get FreePhysicalMemory,TotalVisibleMemorySize /Value',
                                              shell=True)
            mem_lines = mem_cmd.decode().strip().split('\r\r\n')
            total_mem = 0
            for line in mem_lines:
                if 'TotalVisibleMemorySize=' in line:
                    total_mem = int(line.split('=')[1])
                    break
            info['Объём ОЗУ'] = f"{total_mem // 1024} ГБ"
        else:
            # Для Linux/Mac
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if line.startswith('MemTotal:'):
                        mem_kb = int(line.split()[1])
                        info['Объём ОЗУ'] = f"{mem_kb // 1024 // 1024} ГБ"
                        break
    except:
        info['Объём ОЗУ'] = "Не удалось определить"

    return info


def get_network_config_linux():
    """Получение сетевой конфигурации для Linux"""
    config = {}

    try:
        # Получение информации об интерфейсах через ip addr
        ip_output = subprocess.check_output('ip addr', shell=True, encoding='utf-8')

        # Поиск активного интерфейса (не lo)
        lines = ip_output.split('\n')
        current_interface = None
        ip_address = None
        mac_address = None
        subnet_mask = None

        for i, line in enumerate(lines):
            # Поиск интерфейса
            interface_match = re.match(r'\d+:\s+(\w+):', line)
            if interface_match and interface_match.group(1) != 'lo':
                current_interface = interface_match.group(1)

            # Поиск IP адреса и маски
            if current_interface and 'inet ' in line:
                ip_match = re.search(r'inet\s+([0-9.]+)/(\d+)', line)
                if ip_match:
                    ip_address = ip_match.group(1)
                    # Вычисление маски подсети из CIDR
                    cidr = int(ip_match.group(2))
                    mask = '.'.join([str((0xffffffff << (32 - cidr) >> i) & 0xff) for i in [24, 16, 8, 0]])
                    subnet_mask = mask

            # Поиск MAC адреса
            if current_interface and 'link/ether' in line:
                mac_match = re.search(r'link/ether\s+([0-9a-f:]+)', line)
                if mac_match:
                    mac_address = mac_match.group(1)

        config['IP-адрес'] = ip_address if ip_address else socket.gethostbyname(socket.gethostname())
        config['MAC-адрес (физический адрес)'] = mac_address if mac_address else ':'.join(
            ['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2 * 6, 2)][::-1])
        config['Маска подсети'] = subnet_mask if subnet_mask else 'Не определена'

        # Получение основного шлюза через ip route
        try:
            route_output = subprocess.check_output('ip route', shell=True, encoding='utf-8')
            gateway_match = re.search(r'default\s+via\s+([0-9.]+)', route_output)
            if gateway_match:
                config['Основной шлюз'] = gateway_match.group(1)
            else:
                config['Основной шлюз'] = 'Не определен'
        except:
            config['Основной шлюз'] = 'Не определен'

        # Состояние подключения
        try:
            state_output = subprocess.check_output('ip link', shell=True, encoding='utf-8')
            if 'state UP' in state_output:
                config['Состояние подключения (Wi-Fi/Ethernet)'] = 'Подключено'
            else:
                config['Состояние подключения (Wi-Fi/Ethernet)'] = 'Не подключено'
        except:
            config['Состояние подключения (Wi-Fi/Ethernet)'] = 'Неизвестно'

        # Определение типа подключения (Wi-Fi или Ethernet)
        try:
            iw_output = subprocess.check_output('iwconfig 2>/dev/null', shell=True, encoding='utf-8')
            if 'ESSID' in iw_output:
                config['Тип подключения'] = 'Wi-Fi'
            else:
                config['Тип подключения'] = 'Ethernet'
        except:
            config['Тип подключения'] = 'Ethernet'

    except Exception as e:
        config['IP-адрес'] = socket.gethostbyname(socket.gethostname())
        config['MAC-адрес (физический адрес)'] = ':'.join(
            ['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2 * 6, 2)][::-1])
        config['Маска подсети'] = 'Не определена'
        config['Основной шлюз'] = 'Не определен'
        config['Состояние подключения (Wi-Fi/Ethernet)'] = 'Неизвестно'
        config['Тип подключения'] = 'Неизвестно'

    return config


def get_network_config_windows():
    """Получение сетевой конфигурации для Windows"""
    config = {}

    try:
        output = subprocess.check_output('ipconfig /all', shell=True, encoding='cp866')

        # Поиск IPv4 адреса
        ipv4_match = re.search(r'IPv4-адрес[.:\s]+([0-9.]+)', output)
        if ipv4_match:
            config['IP-адрес'] = ipv4_match.group(1)
        else:
            ipv4_match = re.search(r'IPv4 Address[.:\s]+([0-9.]+)', output)
            if ipv4_match:
                config['IP-адрес'] = ipv4_match.group(1)
            else:
                config['IP-адрес'] = socket.gethostbyname(socket.gethostname())

        # Поиск MAC адреса
        mac_match = re.search(r'Физический адрес[.:\s]+([0-9A-F-]+)', output)
        if mac_match:
            config['MAC-адрес (физический адрес)'] = mac_match.group(1).replace('-', ':')
        else:
            mac_match = re.search(r'Physical Address[.:\s]+([0-9A-F-]+)', output)
            if mac_match:
                config['MAC-адрес (физический адрес)'] = mac_match.group(1).replace('-', ':')
            else:
                config['MAC-адрес (физический адрес)'] = ':'.join(
                    ['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2 * 6, 2)][::-1])

        # Поиск состояния подключения
        if re.search(r'Среда\s+:\s+Подключение', output) or re.search(r'Media State[.:\s]+Connected', output):
            config['Состояние подключения (Wi-Fi/Ethernet)'] = 'Подключено'
        else:
            config['Состояние подключения (Wi-Fi/Ethernet)'] = 'Не подключено'

        # Поиск основного шлюза
        gateway_match = re.search(r'Основной шлюз[.:\s]+([0-9.]+)', output)
        if gateway_match:
            config['Основной шлюз'] = gateway_match.group(1)
        else:
            config['Основной шлюз'] = 'Не определен'

        # Маска подсети
        mask_match = re.search(r'Маска подсети[.:\s]+([0-9.]+)', output)
        if mask_match:
            config['Маска подсети'] = mask_match.group(1)
        else:
            config['Маска подсети'] = 'Не определена'

        # Определение типа подключения
        if 'Wireless' in output or 'Беспроводная' in output:
            config['Тип подключения'] = 'Wi-Fi'
        else:
            config['Тип подключения'] = 'Ethernet'

    except Exception as e:
        config['IP-адрес'] = socket.gethostbyname(socket.gethostname())
        config['MAC-адрес (физический адрес)'] = "Не удалось определить"
        config['Состояние подключения (Wi-Fi/Ethernet)'] = "Неизвестно"
        config['Основной шлюз'] = 'Не определен'
        config['Маска подсети'] = 'Не определена'
        config['Тип подключения'] = 'Неизвестно'

    return config


def test_ping_8888():
    """Тестирование ping до 8.8.8.8 с временем ответа и потерей пакетов"""
    result = {
        'Ping 8.8.8.8 — время ответа': 'Недоступен',
        'Ping 8.8.8.8 — потери пакетов': 'Неизвестно'
    }

    try:
        if sys.platform == "win32":
            # Windows - отправляем 4 пакета
            output = subprocess.check_output('ping -n 4 8.8.8.8', shell=True, encoding='cp866',
                                             stderr=subprocess.STDOUT)

            # Поиск времени ответа (среднее)
            time_match = re.search(r'Среднее\s*=\s*(\d+)\s*мс', output)
            if time_match:
                result['Ping 8.8.8.8 — время ответа'] = f"{time_match.group(1)} мс"
            else:
                # Поиск отдельного времени ответа
                time_match = re.search(r'время[=<]\s*(\d+)\s*мс', output)
                if time_match:
                    result['Ping 8.8.8.8 — время ответа'] = f"{time_match.group(1)} мс"

            # Поиск потери пакетов
            loss_match = re.search(r'Потеряно\s*=\s*(\d+)\s*\(', output)
            if loss_match:
                result[
                    'Ping 8.8.8.8 — потери пакетов'] = f"{loss_match.group(1)} из 4 ({int(loss_match.group(1)) * 25}%)"
            else:
                result['Ping 8.8.8.8 — потери пакетов'] = '0 из 4 (0%)'
        else:
            # Linux - отправляем 4 пакета
            output = subprocess.check_output('ping -c 4 8.8.8.8', shell=True, encoding='utf-8',
                                             stderr=subprocess.STDOUT)

            # Поиск времени ответа
            time_match = re.search(r'rtt min/avg/max/mdev\s*=\s*[0-9.]+/([0-9.]+)/', output)
            if time_match:
                result['Ping 8.8.8.8 — время ответа'] = f"{float(time_match.group(1)):.2f} мс"
            else:
                time_match = re.search(r'time[=<](\d+\.?\d*)\s*ms', output)
                if time_match:
                    result['Ping 8.8.8.8 — время ответа'] = f"{time_match.group(1)} мс"

            # Поиск потери пакетов
            loss_match = re.search(r'(\d+)%\s+packet\s+loss', output)
            if loss_match:
                loss_percent = loss_match.group(1)
                result['Ping 8.8.8.8 — потери пакетов'] = f"{loss_percent}%"
            else:
                result['Ping 8.8.8.8 — потери пакетов'] = '0%'

    except Exception as e:
        result['Ping 8.8.8.8 — время ответа'] = 'Недоступен'
        result['Ping 8.8.8.8 — потери пакетов'] = '100%'

    return result


def test_tracert_yandex():
    """Тестирование tracert до yandex.ru с количеством прыжков"""
    result = {
        'Tracert yandex.ru — количество прыжков (hops)': 'Недоступен'
    }

    try:
        if sys.platform == "win32":
            # Windows tracert с максимальным количеством хопов 15
            output = subprocess.check_output('tracert -h 15 yandex.ru', shell=True, encoding='cp866',
                                             stderr=subprocess.STDOUT, timeout=60)

            # Подсчет количества прыжков (строк с номерами)
            lines = output.split('\n')
            hop_count = 0
            for line in lines:
                if re.match(r'\s*\d+\s+', line):
                    hop_count += 1

            if hop_count > 0:
                result['Tracert yandex.ru — количество прыжков (hops)'] = str(hop_count)
            else:
                result['Tracert yandex.ru — количество прыжков (hops)'] = 'Не определен'
        else:
            # Linux traceroute
            output = subprocess.check_output('traceroute -m 15 yandex.ru', shell=True, encoding='utf-8',
                                             stderr=subprocess.STDOUT, timeout=60)

            # Подсчет количества прыжков
            lines = output.split('\n')
            hop_count = 0
            for line in lines:
                if re.match(r'\s*\d+\s+', line):
                    hop_count += 1

            if hop_count > 0:
                result['Tracert yandex.ru — количество прыжков (hops)'] = str(hop_count)
            else:
                result['Tracert yandex.ru — количество прыжков (hops)'] = 'Не определен'

    except subprocess.TimeoutExpired:
        result['Tracert yandex.ru — количество прыжков (hops)'] = 'Превышено время ожидания'
    except Exception as e:
        result['Tracert yandex.ru — количество прыжков (hops)'] = 'Недоступен'

    return result


def print_full_table(system_info, network_config, ping_results, tracert_results):
    """Вывод полной таблицы со всеми параметрами"""
    print("=" * 80)
    print(" " * 25 + "ДИАГНОСТИКА КОМПЬЮТЕРА")
    print("=" * 80)
    print(f"Дата проверки: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}")
    print("=" * 80)

    print("\n" + "-" * 80)
    print(" " * 28 + "ИНФОРМАЦИЯ О СИСТЕМЕ")
    print("-" * 80)
    print(f"{'Параметр':<50} | {'Значение':<25}")
    print("-" * 80)

    for param, value in system_info.items():
        print(f"{param:<50} | {value:<25}")

    print("\n" + "-" * 80)
    print(" " * 28 + "СЕТЕВАЯ КОНФИГУРАЦИЯ")
    print("-" * 80)
    print(f"{'Параметр':<50} | {'Значение':<25}")
    print("-" * 80)

    for param, value in network_config.items():
        print(f"{param:<50} | {value:<25}")

    print("\n" + "-" * 80)
    print(" " * 25 + "РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ СЕТИ")
    print("-" * 80)
    print(f"{'Параметр':<50} | {'Значение':<25}")
    print("-" * 80)

    for param, value in ping_results.items():
        print(f"{param:<50} | {value:<25}")

    for param, value in tracert_results.items():
        print(f"{param:<50} | {value:<25}")

    print("=" * 80)


def save_to_file(system_info, network_config, ping_results, tracert_results, filename="diagnostics.txt"):
    """Сохранение всех результатов в файл"""
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write(" " * 25 + "ДИАГНОСТИКА КОМПЬЮТЕРА\n")
        f.write("=" * 80 + "\n")
        f.write(f"Дата проверки: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")

        f.write("-" * 80 + "\n")
        f.write(" " * 28 + "ИНФОРМАЦИЯ О СИСТЕМЕ\n")
        f.write("-" * 80 + "\n")
        for param, value in system_info.items():
            f.write(f"{param}: {value}\n")

        f.write("\n" + "-" * 80 + "\n")
        f.write(" " * 28 + "СЕТЕВАЯ КОНФИГУРАЦИЯ\n")
        f.write("-" * 80 + "\n")
        for param, value in network_config.items():
            f.write(f"{param}: {value}\n")

        f.write("\n" + "-" * 80 + "\n")
        f.write(" " * 25 + "РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ СЕТИ\n")
        f.write("-" * 80 + "\n")
        for param, value in ping_results.items():
            f.write(f"{param}: {value}\n")
        for param, value in tracert_results.items():
            f.write(f"{param}: {value}\n")

        f.write("=" * 80 + "\n")

    print(f"\nРезультаты сохранены в файл: {filename}")


def main():
    """Основная функция"""
    print("Запуск полной диагностики...\n")

    # Получение информации о системе
    print("Сбор информации о системе...")
    system_info = get_system_info()

    # Получение сетевой конфигурации
    print("Сбор сетевой конфигурации...")
    if sys.platform == "win32":
        network_config = get_network_config_windows()
    else:
        network_config = get_network_config_linux()

    # Тестирование ping
    print("Тестирование ping до 8.8.8.8...")
    ping_results = test_ping_8888()

    # Тестирование tracert
    print("Тестирование tracert до yandex.ru (может занять до 60 секунд)...")
    tracert_results = test_tracert_yandex()

    # Вывод полной таблицы
    print("\n")
    print_full_table(system_info, network_config, ping_results, tracert_results)

    # Сохранение в файл
    save_to_file(system_info, network_config, ping_results, tracert_results)

    print("\nДиагностика завершена!")


if __name__ == "__main__":
    main()
