import subprocess
import psutil
import time
import threading
import sys
from plyer import notification
from datetime import datetime
from .notifications import send_msg

class PacketMonitor:
    def __init__(self):
        self.attack_detected = False  # 공격 감지 여부
        self.last_attack_time = None  # 마지막 공격 감지 시간
        self.SMS_bool = False
        self.total_threshold = 10000  # 총 패킷 수 임계값
        self.average_threshold = 200  # 초당 평균 패킷 수 임계값
        self.packet_count = 0  # 초기 패킷 수 설정
        self.lock = threading.Lock()  # 스레드 안전성을 위한 잠금 장치

    def monitor_packets(self):
        syn_flood1 = "(tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.analysis.retransmission && tcp.dstport == 21)"
        syn_flood2 = "(ip.dst == 192.168.219.102 && tcp.dstport == 5050 && frame.len == 54 && tcp.window_size == 512)"
        ping_of_death = "(icmp && icmp.type == 8)"
        udp_flood = "(udp && frame.len >= 100)"

        interface = self._get_connected_interface(psutil.net_if_stats())
        display_filter = f"{syn_flood1} or {syn_flood2} or {ping_of_death} or {udp_flood}"

        tshark_command = [
            'C:\\Program Files\\Wireshark\\tshark.exe',
            '-i', interface,
            '-Y', display_filter,
            '-T', 'fields',
            '-e', 'frame.len', '-e', 'data.len',
            '-e', 'tcp.flags', '-e', 'icmp.type', '-e', 'udp',
            '-l'
        ]

        try:
            process = subprocess.Popen(tshark_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, universal_newlines=True, bufsize=1)
            unix_start_time = time.time()
            warnings_triggered = [False, False]

            print(f"모니터링 시작 시간: {datetime.fromtimestamp(unix_start_time).strftime('%Y-%m-%d %H:%M:%S')}")
            
            while True:
                line = process.stdout.readline()
                if line.strip():
                    packet_info = line.strip().split('\t')
                    frame_length = int(packet_info[0]) if len(packet_info) > 0 and packet_info[0].isdigit() else 0
                    data_length = int(packet_info[1]) if len(packet_info) > 1 and packet_info[1].isdigit() else 0
                    tcp_flags = packet_info[2] if len(packet_info) > 2 else ""
                    icmp_type = packet_info[3] if len(packet_info) > 3 else ""
                    udp_info = packet_info[4] if len(packet_info) > 4 else ""

                    elapsed_time = time.time() - unix_start_time
                    avg_packets_per_second = self.packet_count / elapsed_time if elapsed_time > 0 else 0

                    if tcp_flags == '0x0002': attack_type = 'SYN Flooding'
                    if icmp_type == '8' and data_length >= 10000: attack_type = 'Ping of Death'
                    if udp_info and frame_length >= 100: attack_type = 'UDP Flooding'
                    self.packet_count += 1

                    if 59 <= elapsed_time % 60 < 61 and data_length >= 10000 and icmp_type and self.packet_count > 15:
                        with self.lock:
                            self.attack_detected = True
                            self._trigger_attack(avg_packets_per_second, attack_type, ping_dl=data_length)
                            unix_start_time = time.time()
                            warnings_triggered = [False, False]
                            self.packet_count = 0

                    if 179 <= elapsed_time % 181 < 181 and self.packet_count >= self.total_threshold and not warnings_triggered[0]:
                        with self.lock:
                            self._trigger_warning(3, 1, self.packet_count, avg_packets_per_second, attack_type)
                            warnings_triggered[0] = True

                    elif 299 <= elapsed_time % 301 < 301 and avg_packets_per_second >= self.average_threshold and warnings_triggered[0] and not warnings_triggered[1]:
                        with self.lock:
                            self._trigger_warning(5, 2, self.packet_count, avg_packets_per_second, attack_type)
                            warnings_triggered[1] = True

                    elif 419 <= elapsed_time % 421 < 421 and avg_packets_per_second >= self.average_threshold and warnings_triggered[1]:
                        with self.lock:
                            self.attack_detected = True
                            self._trigger_attack(avg_packets_per_second, attack_type)
                            unix_start_time = time.time()
                            warnings_triggered = [False, False]
                            self.packet_count = 0
                    elif elapsed_time >= 421:
                        unix_start_time = time.time()
                        warnings_triggered = [False, False]
                        self.packet_count = 0
        except Exception as e:
            print(f"오류 발생: {e}")
            sys.stdout.flush()

    def _trigger_warning(self, m, warning_level, packet_count, avg_packets_per_second, atck_type):
        """트래픽 상태에 따른 경고 처리"""
        message = f"{warning_level}차 경고:\n{m}분동안 총 패킷 {packet_count}개 수신\n{avg_packets_per_second:.2f}pps\n공격유형: {atck_type}\n{datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')}"
        print(message)
        self.show_notification(False, '서버 트래픽 알림', message)

    def _trigger_attack(self, avg_packets_per_second, atck_type, ping_dl=None):
        """공격 감지 처리"""
        message = f"DDoS 공격 감지!\n{avg_packets_per_second:.2f}pps\n공격유형: {atck_type}\n{datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')}"
        if ping_dl: message += f"\n데이터 크기 :{ping_dl}byte"
        print(message)
        send_msg(message, atck_type)
        self.show_notification(True, '서버 트래픽 알림', message)
        self.last_attack_time = time.time()

    def show_notification(self, n,  title, message):
        """알림 팝업을 표시하는 함수"""
        if n: icon = 'ddos.ico'
        else: icon = 'warning.ico'

        notification.notify(
            title=title,
            message=message,
            app_name="트래픽 모니터링",
            app_icon=f'assets/{icon}',
            timeout=15  # 초
        )

    def start_monitoring(self):
        """패킷 모니터링을 별도의 스레드에서 시작"""
        thread = threading.Thread(target=self.monitor_packets)
        thread.daemon = True
        thread.start()

    def is_attack_detected(self):
        """스레드 안전하게 공격 감지 상태 확인"""
        with self.lock:
            return self.attack_detected

    def _get_connected_interface(self, interfaces):
        """연결된 네트워크 인터페이스 찾기"""
        for interface, stats in interfaces.items():
            if stats.isup and interface in ["Ethernet 1", "Ethernet 2", "ens160", "enp3s0", "Wi-Fi"]:
                return interface
        return None

# 패킷 모니터링 인스턴스 생성
packet_monitor = PacketMonitor()