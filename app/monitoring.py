# monitoring.py
import asyncio
import pyshark
import psutil
import time
import threading
import sys
from datetime import datetime

class PacketMonitor:
    def __init__(self):
        self.attack_detected = False  # 공격이 감지되었는지 여부
        self.last_attack_time = None  # 마지막 공격 시간
        self.total_threshold = 1000  # 총 패킷 임계값
        self.average_threshold = 50  # 초당 평균 패킷 수 임계값
        self.packet_count = 0  # 패킷 수 초기화
        self.lock = threading.Lock()

    def monitor_packets(self):
        try:
            # 스레드에서 asyncio 이벤트 루프를 수동으로 설정
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            interfaces = psutil.net_if_stats()
            connected_interface = self._get_connected_interface(interfaces)

            capture = pyshark.LiveCapture(
                interface=connected_interface,
                display_filter="tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.dstport == 21 && tcp.analysis.retransmission"
            )

            while True:
                unix_start_time = time.time()
                print(f"모니터링 시작 시간: {datetime.fromtimestamp(unix_start_time).strftime('%Y-%m-%d %H:%M:%S')}")
                sys.stdout.flush()

                for packet in capture.sniff_continuously():
                    self.packet_count += 1
                    elapsed_time = time.time() - unix_start_time
                    print(f"경과 시간: {elapsed_time:.4f} sec, 총 패킷 수: {self.packet_count}")
                    sys.stdout.flush()

                    if elapsed_time >= 60:
                        avg_packets_per_second = self.packet_count / elapsed_time
                        print(f'초당 평균 패킷 수 : {avg_packets_per_second}')
                        if self.packet_count >= self.total_threshold:
                            print(f'총 패킷 수 : {self.packet_count}')
                            if avg_packets_per_second >= self.average_threshold:
                                # 공격 감지, 스레드 안전하게 상태 변경
                                with self.lock:
                                    self.attack_detected = True
                                    print(f"DDoS 공격 감지! attack_detected: {self.attack_detected}")
                                    self.last_attack_time = time.time()
                            break
                        else:
                            with self.lock:
                                self.last_attack_time = time.time()  # 마지막 공격 시간 기록

                # 패킷 모니터링 재시작을 위한 준비 (임계값 초기화 등)
                print("3분 대기 후 패킷 모니터링 재시작")
                sys.stdout.flush()
                time.sleep(5)
                self.packet_count = 0  # 패킷 수 초기화
        
        except Exception as e:
            print(f"오류 발생: {e}")
            sys.stdout.flush()

    def start_monitoring(self):
        thread = threading.Thread(target=self.monitor_packets)
        thread.daemon = True
        thread.start()

    def is_attack_detected(self):
        """스레드 안전하게 attack_detected 상태 확인"""
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