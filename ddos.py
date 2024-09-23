import pyshark
from scapy.all import wrpcap, Ether
import os

# PCAP 파일 경로 설정 (절대 경로로 설정 권장)
input_pcap_file = '/Users/12000/captcha_website/DDoS_Detection/패킷2.pcapng'  # 입력 pcapng 파일 경로
output_pcap_file = '/Users/12000/captcha_website/DDoS_Detection/필터링된 패킷.pcapng'  # 필터링된 패킷을 저장할 pcapng 파일 경로

# Pyshark를 이용해 기존 pcap 파일에서 패킷 읽기
# 필터 조건: SYN 플래그가 설정되고 ACK 플래그가 없으며, 목적지 포트는 21번이고 재전송된 패킷
# pyshark에서 패킷을 캡처할 때, use_json=True 및 include_raw=True로 설정
capture = pyshark.FileCapture(
    input_pcap_file,
    display_filter="tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.dstport == 21 && tcp.analysis.retransmission",
    use_json=True,  # JSON 포맷으로 패킷을 파싱
    include_raw=True  # 원시 데이터 포함
)

# Scapy를 이용해 패킷을 저장하기 위한 리스트
filtered_packets = []

# 패킷 추출 및 변환
for packet in capture:
    try:
        # pyshark에서 패킷의 원시 데이터를 가져옴
        raw_packet = packet.get_raw_packet()  # 패킷의 원시 데이터를 가져옴
        filtered_packets.append(Ether(raw_packet))  # scapy의 Ether 객체로 변환하여 저장
    except AttributeError:
        continue  # 만약 get_raw_packet()을 사용할 수 없으면 패킷을 건너뜀


# 추출된 패킷을 새로운 pcapng 파일로 저장
if filtered_packets:
    wrpcap(output_pcap_file, filtered_packets)
    print(f"필터링된 패킷을 {output_pcap_file}에 저장했습니다.")
else:
    print("필터링된 패킷이 없습니다.")

# 현재 디렉토리 확인 (작업 경로에서 파일이 저장된 경로를 확인)
print(f"현재 작업 디렉토리: {os.getcwd()}")
print(f"저장된 파일 확인: {os.listdir()}")