from .notifications import send_msg
import asyncio
import pyshark
import psutil
import time
import threading
import sys, keyboard, win32api
from datetime import datetime
from plyer import notification

class PacketMonitor:
    def __init__(self):
        self.attack_detected = False  # 공격이 감지되었는지 여부
        self.last_attack_time = None  # 마지막 공격 시간
        self.SMS_bool = False
        self.total_threshold = 200  # 총 패킷 임계값 1000
        self.average_threshold = 20  # 초당 평균 패킷 수 임계값 50
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
                warnings_triggered = [False, False]
                print(f"모니터링 시작 시간: {datetime.fromtimestamp(unix_start_time).strftime('%Y-%m-%d %H:%M:%S')}")
                sys.stdout.flush()

                for packet in capture.sniff_continuously():
                    self.packet_count += 1
                    elapsed_time = time.time() - unix_start_time

                    avg_packets_per_second = self.packet_count / elapsed_time             
                    
                    if 17 <= elapsed_time < 19 and self.packet_count >= self.total_threshold and not warnings_triggered[0]: # 1차필터 : 3분동안 총 패킷개수 기준 설정
                        print(f'1차 경고 : [3분경과]총 패킷 {self.packet_count}개 수신')
                        notification.notify(
                            title = '트래픽 상태 알림',
                            message = f'1차 경고 : [3분경과] 총 패킷 {self.packet_count}개 수신',
                            app_name = "앱 이름",
                            app_icon = 'C:\\Users\\12000\\captcha_website\\DDoS_Detection\\warning.ico',
                            timeout = 5,  # seconds
                        )
                        warnings_triggered[0] = True
                    elif 29 <= elapsed_time < 31 and avg_packets_per_second >= self.average_threshold and not warnings_triggered[1]: # 2차필터 : 5분동안 초당 평균 패킷개수 기준 설정
                        print('2차 경고 : [5분경과] 초당 평균 패킷 %.2f개'%avg_packets_per_second)
                        notification.notify(
                            title = '트래픽 상태 알림',
                            message = '2차 경고 : [5분경과] 초당 평균 패킷 %.2f개'%avg_packets_per_second,
                            app_name = "앱 이름",
                            app_icon = 'C:\\Users\\12000\\captcha_website\\DDoS_Detection\\warning.ico',
                            timeout = 5,  # seconds
                        )
                        warnings_triggered[1] = True
                    elif 41 <= elapsed_time < 43 and avg_packets_per_second >= self.average_threshold: # 3차필터 : 7분동안 초당 평균 패킷개수 기준 설정
                        # 공격 감지, 스레드 안전하게 상태 변경
                        with self.lock:
                            self.attack_detected = True
                            if not self.SMS_bool:
                                send_msg()
                                self.SMS_bool = True
                            print(f"DDoS 공격 감지! attack_detected: {self.attack_detected}")
                            win32api.MessageBox(0, "DDoS 공격 감지! attack_detected", "트래픽 상태 알림", 48)
                            self.last_attack_time = time.time()
                        break
                    # else:
                    #     with self.lock:
                    #         self.last_attack_time = time.time()  # 마지막 공격 시간 기록

                # 패킷 모니터링 재시작을 위한 준비 (임계값 초기화 등)
                if keyboard.is_pressed('ctrl') and keyboard.is_pressed('c'):
                    print('서버 종료')
                    sys.stdout.flush()
                    break
                else:
                    # print("3분 대기 후 패킷 모니터링 재시작")
                    # sys.stdout.flush()
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