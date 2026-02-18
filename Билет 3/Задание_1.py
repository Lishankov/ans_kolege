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

    # Версия ядра
    info['Версия ядра'] = platform.release()

    # Архитектура системы
    info['Архитектура системы'] = platform.machine()

    # Процессор - получение реального названия модели
    try:
        if sys.platform == "win32":
            # Для Windows
            cpu_cmd = subprocess.check_output('wmic cpu get name', shell=True, encoding='cp866')
            cpu_lines = cpu_cmd.strip().split('\n')
            for line in cpu_lines:
                if line.strip() and 'Name' not in line:
                    info['Процессор'] = line.strip()
                    break
        else:
            # Для Linux - читаем из /proc/cpuinfo
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if line.startswith('model name') or line.startswith('Model name'):
                        info['Процессор'] = line.split(':')[1].strip()
                        break
                else:
                    info['Процессор'] = platform.processor() if platform.processor() else 'Не определен'
    except:
        info['Процессор'] = platform.processor() if platform.processor() else 'Не определен'

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
            # Для Linux
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if line.startswith('MemTotal:'):
                        mem_kb = int(line.split()[1])
                        info['Объём ОЗУ'] = f"{mem_kb // 1024 // 1024} ГБ"
                        break
    except:
        info['Объём ОЗУ'] = "Не удалось определить"

    return info


def get_network_info():
    """Получение сетевой информации"""
    info = {}

    try:
        if sys.platform == "win32":
            # Для Windows
            output = subprocess.check_output('ipconfig /all', shell=True, encoding='cp866')

            # IP-адрес
            ipv4_match = re.search(r'IPv4-адрес[.:\s]+([0-9.]+)', output)
            if ipv4_match:
                info['IP-адрес'] = ipv4_match.group(1)
            else:
                ipv4_match = re.search(r'IPv4 Address[.:\s]+([0-9.]+)', output)
                info['IP-адрес'] = ipv4_match.group(1) if ipv4_match else socket.gethostbyname(socket.gethostname())

            # MAC-адрес
            mac_match = re.search(r'Физический адрес[.:\s]+([0-9A-F-]+)', output)
            if mac_match:
                info['MAC-адрес'] = mac_match.group(1).replace('-', ':')
            else:
                mac_match = re.search(r'Physical Address[.:\s]+([0-9A-F-]+)', output)
                info['MAC-адрес'] = mac_match.group(1).replace('-', ':') if mac_match else 'Не определен'

            # Маска подсети
            mask_match = re.search(r'Маска подсети[.:\s]+([0-9.]+)', output)
            info['Маска подсети'] = mask_match.group(1) if mask_match else 'Не определена'

            # Основной шлюз
            gateway_match = re.search(r'Основной шлюз[.:\s]+([0-9.]+)', output)
            info['Основной шлюз'] = gateway_match.group(1) if gateway_match else 'Не определен'

            # Сетевое подключение
            if re.search(r'Среда\s+:\s+Подключение', output) or re.search(r'Media State[.:\s]+Connected', output):
                info['Сетевое подключение'] = 'Подключено'
            else:
                info['Сетевое подключение'] = 'Не подключено'

        else:
            # Для Linux
            ip_output = subprocess.check_output('ip addr', shell=True, encoding='utf-8')

            lines = ip_output.split('\n')
            current_interface = None
            ip_address = None
            mac_address = None
            subnet_mask = None

            for line in lines:
                interface_match = re.match(r'\d+:\s+(\w+):', line)
                if interface_match and interface_match.group(1) != 'lo':
                    current_interface = interface_match.group(1)

                if current_interface and 'inet ' in line:
                    ip_match = re.search(r'inet\s+([0-9.]+)/(\d+)', line)
                    if ip_match:
                        ip_address = ip_match.group(1)
                        cidr = int(ip_match.group(2))
                        mask = '.'.join([str((0xffffffff << (32 - cidr) >> i) & 0xff) for i in [24, 16, 8, 0]])
                        subnet_mask = mask

                if current_interface and 'link/ether' in line:
                    mac_match = re.search(r'link/ether\s+([0-9a-f:]+)', line)
                    if mac_match:
                        mac_address = mac_match.group(1)

            info['IP-адрес'] = ip_address if ip_address else socket.gethostbyname(socket.gethostname())
            info['MAC-адрес'] = mac_address if mac_address else 'Не определен'
            info['Маска подсети'] = subnet_mask if subnet_mask else 'Не определена'

            # Основной шлюз
            try:
                route_output = subprocess.check_output('ip route', shell=True, encoding='utf-8')
                gateway_match = re.search(r'default\s+via\s+([0-9.]+)', route_output)
                info['Основной шлюз'] = gateway_match.group(1) if gateway_match else 'Не определен'
            except:
                info['Основной шлюз'] = 'Не определен'

            # Сетевое подключение
            try:
                state_output = subprocess.check_output('ip link', shell=True, encoding='utf-8')
                info['Сетевое подключение'] = 'Подключено' if 'state UP' in state_output else 'Не подключено'
            except:
                info['Сетевое подключение'] = 'Неизвестно'

    except Exception as e:
        info['IP-адрес'] = 'Не определен'
        info['MAC-адрес'] = 'Не определен'
        info['Маска подсети'] = 'Не определена'
        info['Основной шлюз'] = 'Не определен'
        info['Сетевое подключение'] = 'Неизвестно'

    return info


def test_ping_8888():
    """Тестирование ping до 8.8.8.8"""
    result = {
        'Ping 8.8.8.8': 'Недоступен',
        'Потери пакетов': 'Неизвестно'
    }

    try:
        if sys.platform == "win32":
            output = subprocess.check_output('ping -n 4 8.8.8.8', shell=True, encoding='cp866',
                                             stderr=subprocess.STDOUT)

            time_match = re.search(r'Среднее\s*=\s*(\d+)\s*мс', output)
            if time_match:
                result['Ping 8.8.8.8'] = f"{time_match.group(1)} мс"
            else:
                time_match = re.search(r'время[=<]\s*(\d+)\s*мс', output)
                if time_match:
                    result['Ping 8.8.8.8'] = f"{time_match.group(1)} мс"

            loss_match = re.search(r'Потеряно\s*=\s*(\d+)\s*\(', output)
            if loss_match:
                result['Потери пакетов'] = f"{loss_match.group(1)} из 4 ({int(loss_match.group(1)) * 25}%)"
            else:
                result['Потери пакетов'] = '0 из 4 (0%)'
        else:
            output = subprocess.check_output('ping -c 4 8.8.8.8', shell=True, encoding='utf-8',
                                             stderr=subprocess.STDOUT)

            time_match = re.search(r'rtt min/avg/max/mdev\s*=\s*[0-9.]+/([0-9.]+)/', output)
            if time_match:
                result['Ping 8.8.8.8'] = f"{float(time_match.group(1)):.2f} мс"
            else:
                time_match = re.search(r'time[=<](\d+\.?\d*)\s*ms', output)
                if time_match:
                    result['Ping 8.8.8.8'] = f"{time_match.group(1)} мс"

            loss_match = re.search(r'(\d+)%\s+packet\s+loss', output)
            if loss_match:
                result['Потери пакетов'] = f"{loss_match.group(1)}%"
            else:
                result['Потери пакетов'] = '0%'

    except Exception as e:
        result['Ping 8.8.8.8'] = 'Недоступен'
        result['Потери пакетов'] = '100%'

    return result


def test_tracert_yandex():
    """Тестирование tracert до yandex.ru"""
    result = {
        'Количество переходов (HOPS)': 'Недоступен'
    }

    try:
        if sys.platform == "win32":
            output = subprocess.check_output('tracert -h 15 yandex.ru', shell=True, encoding='cp866',
                                             stderr=subprocess.STDOUT, timeout=60)
            lines = output.split('\n')
            hop_count = 0
            for line in lines:
                if re.match(r'\s*\d+\s+', line):
                    hop_count += 1
            result['Количество переходов (HOPS)'] = str(hop_count) if hop_count > 0 else 'Не определен'
        else:
            output = subprocess.check_output('traceroute -m 15 yandex.ru', shell=True, encoding='utf-8',
                                             stderr=subprocess.STDOUT, timeout=60)
            lines = output.split('\n')
            hop_count = 0
            for line in lines:
                if re.match(r'\s*\d+\s+', line):
                    hop_count += 1
            result['Количество переходов (HOPS)'] = str(hop_count) if hop_count > 0 else 'Не определен'

    except subprocess.TimeoutExpired:
        result['Количество переходов (HOPS)'] = 'Превышено время ожидания'
    except Exception as e:
        result['Количество переходов (HOPS)'] = 'Недоступен'

    return result


def print_table(system_info, network_info, ping_results, tracert_results):
    """Вывод итоговой таблицы"""
    print("=" * 70)
    print(" " * 20 + "Итоговая таблица диагностики")
    print("=" * 70)
    print(f"{'Параметр':<40} | {'Значение':<25}")
    print("-" * 70)

    # Системная информация
    print(f"{'Операционная система':<40} | {system_info.get('Операционная система', 'Не определена'):<25}")
    print(f"{'Версия ядра':<40} | {system_info.get('Версия ядра', 'Не определена'):<25}")
    print(f"{'Архитектура системы':<40} | {system_info.get('Архитектура системы', 'Не определена'):<25}")
    print(f"{'Процессор':<40} | {system_info.get('Процессор', 'Не определен'):<25}")
    print(f"{'Объём ОЗУ':<40} | {system_info.get('Объём ОЗУ', 'Не определен'):<25}")
    print("-" * 70)

    # Сетевая информация
    print(f"{'Сетевое подключение':<40} | {network_info.get('Сетевое подключение', 'Неизвестно'):<25}")
    print(f"{'IP-адрес':<40} | {network_info.get('IP-адрес', 'Не определен'):<25}")
    print(f"{'Маска подсети':<40} | {network_info.get('Маска подсети', 'Не определена'):<25}")
    print(f"{'Основной шлюз':<40} | {network_info.get('Основной шлюз', 'Не определен'):<25}")
    print(f"{'MAC-адрес':<40} | {network_info.get('MAC-адрес', 'Не определен'):<25}")
    print("-" * 70)

    # Результаты тестирования
    print(f"{'Ping 8.8.8.8':<40} | {ping_results.get('Ping 8.8.8.8', 'Недоступен'):<25}")
    print(f"{'Потери пакетов':<40} | {ping_results.get('Потери пакетов', 'Неизвестно'):<25}")
    print(
        f"{'Количество переходов (HOPS)':<40} | {tracert_results.get('Количество переходов (HOPS)', 'Недоступен'):<25}")
    print("=" * 70)


def save_to_file(system_info, network_info, ping_results, tracert_results, filename="diagnostics.txt"):
    """Сохранение результатов в файл"""
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("Итоговая таблица диагностики\n")
        f.write("=" * 70 + "\n")
        f.write(f"{'Параметр':<40} | {'Значение':<25}\n")
        f.write("-" * 70 + "\n")

        f.write(f"{'Операционная система':<40} | {system_info.get('Операционная система', 'Не определена'):<25}\n")
        f.write(f"{'Версия ядра':<40} | {system_info.get('Версия ядра', 'Не определена'):<25}\n")
        f.write(f"{'Архитектура системы':<40} | {system_info.get('Архитектура системы', 'Не определена'):<25}\n")
        f.write(f"{'Процессор':<40} | {system_info.get('Процессор', 'Не определен'):<25}\n")
        f.write(f"{'Объём ОЗУ':<40} | {system_info.get('Объём ОЗУ', 'Не определен'):<25}\n")
        f.write("-" * 70 + "\n")

        f.write(f"{'Сетевое подключение':<40} | {network_info.get('Сетевое подключение', 'Неизвестно'):<25}\n")
        f.write(f"{'IP-адрес':<40} | {network_info.get('IP-адрес', 'Не определен'):<25}\n")
        f.write(f"{'Маска подсети':<40} | {network_info.get('Маска подсети', 'Не определена'):<25}\n")
        f.write(f"{'Основной шлюз':<40} | {network_info.get('Основной шлюз', 'Не определен'):<25}\n")
        f.write(f"{'MAC-адрес':<40} | {network_info.get('MAC-адрес', 'Не определен'):<25}\n")
        f.write("-" * 70 + "\n")

        f.write(f"{'Ping 8.8.8.8':<40} | {ping_results.get('Ping 8.8.8.8', 'Недоступен'):<25}\n")
        f.write(f"{'Потери пакетов':<40} | {ping_results.get('Потери пакетов', 'Неизвестно'):<25}\n")
        f.write(
            f"{'Количество переходов (HOPS)':<40} | {tracert_results.get('Количество переходов (HOPS)', 'Недоступен'):<25}\n")
        f.write("=" * 70 + "\n")

    print(f"\nРезультаты сохранены в файл: {filename}")


def main():
    """Основная функция"""
    print("Запуск диагностики...\n")

    # Получение информации
    system_info = get_system_info()
    network_info = get_network_info()
    ping_results = test_ping_8888()
    tracert_results = test_tracert_yandex()

    # Вывод таблицы
    print_table(system_info, network_info, ping_results, tracert_results)

    # Сохранение в файл
    save_to_file(system_info, network_info, ping_results, tracert_results)

    print("\nДиагностика завершена!")


if __name__ == "__main__":
    main()
