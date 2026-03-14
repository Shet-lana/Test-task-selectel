from scapy.all import rdpcap
import re
from collections import Counter

packets = rdpcap('cap3.pcapng')

# 1. HTTP-запросы и ответы
http_requests = []
http_responses = []

# 2. ARP-запросы
arp_requests = []
arp_responses = []

# 3. DHCP
dhcp_transactions = []

# 4. TCP-сессии (порты, последовательности)
tcp_sessions = {}

# 5. TLS/SSL
tls_handshakes = 0

# 6. Статистика по MAC и IP
mac_stats = Counter()
ip_stats = Counter()
port_stats = Counter()

for p in packets:
    # Статистика по MAC и IP
    if p.haslayer('Ethernet'):
        mac_stats[p['Ethernet'].src] += 1
        mac_stats[p['Ethernet'].dst] += 1
    if p.haslayer('IP'):
        ip_stats[p['IP'].src] += 1
        ip_stats[p['IP'].dst] += 1
        if p.haslayer('TCP'):
            port_stats[p['TCP'].sport] += 1
            port_stats[p['TCP'].dport] += 1

    # ARP
    if p.haslayer('ARP'):
        if p['ARP'].op == 1:  # request
            arp_requests.append(f"{p['ARP'].psrc} → {p['ARP'].pdst}")
        elif p['ARP'].op == 2:  # reply
            arp_responses.append(f"{p['ARP'].psrc} → {p['ARP'].pdst}")

    # DHCP
    if p.haslayer('BOOTP'):
        dhcp_transactions.append(f"{p['BOOTP'].yiaddr} {p['BOOTP'].op}")

    # HTTP
    if p.haslayer('TCP') and p.haslayer('Raw'):
        data = p['Raw'].load.decode('utf-8', errors='ignore')
        if 'GET' in data or 'POST' in data:
            http_requests.append(data.split('\n'))  # первая строка
        if 'HTTP/' in data:
            http_responses.append(data.split('\n'))

    # TCP-сессии
    if p.haslayer('TCP'):
        key = f"{p['IP'].src}:{p['TCP'].sport} → {p['IP'].dst}:{p['TCP'].dport}"
        if key not in tcp_sessions:
            tcp_sessions[key] = {'seq': p['TCP'].seq, 'ack': p['TCP'].ack, 'count': 0}
        tcp_sessions[key]['count'] += 1

    # TLS/SSL
    if p.haslayer('TLS'):
        tls_handshakes += 1

# Вывод расширенного отчёта
print("=" * 60)
print("РАСШИРЕННЫЙ АНАЛИЗ PCAP-ФАЙЛА")
print("=" * 60)

print(f"\n=== HTTP-трафик ===")
print("Запросы:")
for r in http_requests:
    print(f"  {r}")
print("Ответы:")
for r in http_responses:
    print(f"  {r}")

print(f"\n=== ARP-трафик ===")
print("Запросы:")
for r in arp_requests:
    print(f"  {r}")
print("Ответы:")
for r in arp_responses:
    print(f"  {r}")

print(f"\n=== DHCP ===")
for t in dhcp_transactions:
    print(f"  {t}")

print(f"\n=== TCP-сессии ===")
for k, v in tcp_sessions.items():
    print(f"  {k}: seq={v['seq']}, ack={v['ack']}, пакетов={v['count']}")

print(f"\n=== TLS/SSL ===")
print(f"Рукопожатий: {tls_handshakes}")

print(f"\n=== Статистика ===")
print(f"MAC-адреса: {dict(mac_stats)}")
print(f"IP-адреса: {dict(ip_stats)}")
print(f"Порты: {dict(port_stats)}")

print(f"\nВсего пакетов: {len(packets)}")
