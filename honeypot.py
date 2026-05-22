#!/usr/bin/env python3
import logging
import json
import asyncio
import threading
import struct
import socket
import random
from datetime import datetime, timezone
from collections import defaultdict

# ================
#   КОНФИГУРАЦИЯ
# ================
BIND_HOST = '0.0.0.0'
TRAP_PORTS = [2222, 2223, 8080]

# Баннеры для маскировки
BANNERS = {
    2222: [b"SSH-2.0-Cisco-1.25\r\n", b"SSH-2.0-Dropbear_2019.78\r\n"],
    2223: [b"SSH-2.0-ROSSSH\r\n", b"SSH-2.0-OpenSSH_3.4p1\r\n"],
    8080: [b"Apache/1.3.41 (Unix)\r\n", b"Microsoft-IIS/5.0\r\n", b"nginx/0.8.53\r\n"],
}

# Сигнатуры угроз
THREAT_DB = {
    b'nmap': 'NMAP_PROBE',
    b'get / http': 'HTTP_PROBE',
    b'head / http': 'HTTP_HEAD',
    b'options /': 'HTTP_OPTIONS',
    b'\x00\x00\x00\x0c': 'SSH_BINARY_PROBE',
    b'ssh-2.0-nmap': 'NMAP_SSH',
    b'root:': 'BRUTEFORCE_ATTEMPT',
    b'admin:': 'BRUTEFORCE_ATTEMPT',
}

# ================
#   ЛОГГИРОВАНИЕ
# ================
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "lvl": record.levelname,
            "src": getattr(record, 'src', '0.0.0.0:0'),
            "event": record.msg,
            "threat": getattr(record, 'threat', ''),
            "data": getattr(record, 'data', ''),
        }
        return json.dumps(log)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('HONEYPOT')
for h in logger.handlers[:]:
    logger.removeHandler(h)
handler = logging.StreamHandler()
handler.setFormatter(JsonFormatter())
logger.addHandler(handler)

# ===========
#   СНИФФЕР
# ===========
class SynDetector(threading.Thread):
    """Перехватывает SYN-сканы через AF_PACKET"""
    def __init__(self, ports):
        super().__init__(daemon=True)
        self.ports = set(ports)
        self.stats = defaultdict(list)
        
    def run(self):
        try:
            # AF_PACKET с ETH_P_ALL для захвата TCP
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.bind(('eth0', 0))
            logger.info("SYN_DETECTOR_STARTED", extra={'src': 'eth0'})
            
            while True:
                pkt, _ = sock.recvfrom(65535)
                self._parse(pkt)
        except Exception as e:
            logger.error(f"SYN_DETECTOR_FAILED: {e}", extra={'src': 'kernel'})
    
    def _parse(self, pkt):
        if len(pkt) < 34:
            return
        
        # Ethernet type
        if struct.unpack('!H', pkt[12:14])[0] != 0x0800:
            return
        
        # IP header
        ip_hdr = pkt[14:34]
        if ip_hdr[9] != 6:  # TCP only
            return
        
        # TCP header
        ip_len = (ip_hdr[0] & 0x0F) * 4
        tcp_start = 14 + ip_len
        
        if len(pkt) < tcp_start + 20:
            return
        
        tcp_hdr = pkt[tcp_start:tcp_start+20]
        dst_port = struct.unpack('!H', tcp_hdr[2:4])[0]
        
        if dst_port not in self.ports:
            return
        
        flags = tcp_hdr[13]
        src_ip = socket.inet_ntoa(ip_hdr[12:16])
        
        # Классификация сканирования по TCP-флагам
        if (flags & 0x02) and not (flags & 0x10):  # SYN without ACK
            self._alert(src_ip, 'SYN_SCAN')
        elif (flags & 0x10) and not (flags & 0x02):  # ACK without SYN
            self._alert(src_ip, 'ACK_SCAN')
        elif flags == 0:  # NULL
            self._alert(src_ip, 'NULL_SCAN')
        elif (flags & 0x29) == 0x29:  # XMAS
            self._alert(src_ip, 'XMAS_SCAN')
        elif (flags & 0x01):  # FIN
            self._alert(src_ip, 'FIN_SCAN')
    
    def _alert(self, ip, scan_type):
        now = datetime.now(timezone.utc)
        self.stats[ip].append(now)
        # Очистка старых записей
        self.stats[ip] = [t for t in self.stats[ip] if (now - t).seconds < 10]
        
        count = len(self.stats[ip])
        if count == 1 or count % 10 == 0:  # Логирование первого и каждого 10-го
            logger.warning(f"SCAN_DETECTED", extra={
                'src': f'{ip}:0',
                'threat': scan_type,
                'data': f'count={count}'
            })

# ============
#   HONEYPOT
# ============
class Honeypot:
    async def handle(self, reader, writer, port):
        addr = writer.get_extra_info('peername')
        if not addr:
            return
        
        src_ip, src_port = addr[0], addr[1]
        
        try:
            # Отправка баннера
            banner = random.choice(BANNERS.get(port, [b"OK\r\n"]))
            writer.write(banner)
            await writer.drain()
            
            # Читение ответа
            data = await asyncio.wait_for(reader.read(4096), timeout=3.0)
            
            if data:
                # Анализ сигнатур
                detected = []
                for sig, threat in THREAT_DB.items():
                    if sig in data.lower():
                        detected.append(threat)
                
                if detected:
                    logger.warning(f"THREAT_DETECTED", extra={
                        'src': f'{src_ip}:{src_port}',
                        'threat': ','.join(detected),
                        'data': data[:100].hex()
                    })
                else:
                    logger.info(f"PAYLOAD_RECEIVED", extra={
                        'src': f'{src_ip}:{src_port}',
                        'data': data[:100].hex()
                    })
                
                # Ответ-ловушка
                if port in [2222, 2223]:
                    writer.write(b'\x00\x00\x00\x0c\n\x00\x00\x00\x00\x00\x00\x00\x00')
                elif port == 8080:
                    writer.write(b'HTTP/1.0 400 Bad Request\r\nServer: Apache\r\n\r\n')
                await writer.drain()
            else:
                logger.warning(f"EMPTY_CONNECTION", extra={
                    'src': f'{src_ip}:{src_port}',
                    'threat': 'POSSIBLE_PORT_SCAN'
                })
                
        except asyncio.TimeoutError:
            logger.info(f"TIMEOUT", extra={'src': f'{src_ip}:{src_port}'})
        except Exception as e:
            logger.error(f"ERROR: {e}", extra={'src': f'{src_ip}:{src_port}'})
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def start_port(self, port):
        server = await asyncio.start_server(
            lambda r, w: self.handle(r, w, port),
            BIND_HOST, port
        )
        logger.info(f"PORT_OPEN", extra={'src': f'{BIND_HOST}:{port}'})
        async with server:
            await server.serve_forever()
    
    async def start(self):
        tasks = [asyncio.create_task(self.start_port(p)) for p in TRAP_PORTS]
        await asyncio.gather(*tasks)

if __name__ == '__main__':
    print(f"Ports: {TRAP_PORTS}")
    print("=" * 50)
    
    # Запуск SYN-детектора
    detector = SynDetector(TRAP_PORTS)
    detector.start()
    
    # Запуск сервера
    honeypot = Honeypot()
    try:
        asyncio.run(honeypot.start())
    except KeyboardInterrupt:
        print("\n[LAB] Shutdown")
