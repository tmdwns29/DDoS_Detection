# app = Flask(__name__)

# # Define the path for the whitelist file
# whitelist_file = 'whitelist.txt'

# @app.route('/', methods=['GET', 'POST'])
# def home():
#     text = None
#     if request.method == 'POST':
#         captcha_response = request.form['g-recaptcha-response']
#         secret_key = '6LdtPjgqAAAAAPLNFUfhrhxMYcSzIrQUkleG0VrL'
#         verify_url = 'https://www.google.com/recaptcha/api/siteverify'
#         data = {'secret': secret_key, 'response': captcha_response}
#         response = requests.post(verify_url, data=data)
#         result = response.json()

#         if result.get('success'):
#             text = request.form['user_input']
#             client_ip = request.remote_addr

#             # Add the client IP to the whitelist file
#             with open(whitelist_file, 'a+') as f:
#                 f.seek(0)  # 파일의 처음으로 이동
#                 whitelisted_ips = f.read().splitlines()
                
#                 if client_ip not in whitelisted_ips:
#                     f.write(client_ip + '\n')

#             print(f"사용자 입력: {text}, IP {client_ip} added to whitelist")
#         else:
#             return "<script>alert('CAPTCHA 검증 실패!!'); history.back();</script>", 400
#     return render_template('index.html', text=text)

# if __name__ == '__main__':
#     if not os.path.exists('uploads'):
#         os.makedirs('uploads')
#     app.run(host='0.0.0.0', port=5050, debug=True)


################################### 원본
# from flask import Flask, render_template, request, redirect, url_for, make_response
# import time, os, requests, uuid

# app = Flask(__name__)

# whitelist_file = 'whitelist.txt'

# @app.route('/', methods=['GET', 'POST'])
# def home():
#     text = None
#     if request.method == 'POST':
#         captcha_response = request.form['g-recaptcha-response']
#         secret_key = '6LdtPjgqAAAAAPLNFUfhrhxMYcSzIrQUkleG0VrL'
#         verify_url = 'https://www.google.com/recaptcha/api/siteverify'
#         data = {'secret': secret_key, 'response': captcha_response}
#         response = requests.post(verify_url, data=data)
#         result = response.json()

#         if result.get('success'):
#             text = request.form['user_input']
#             client_ip = request.remote_addr

#             # Add the client IP to the whitelist file
#             with open(whitelist_file, 'a+') as f:
#                 f.seek(0)  # 파일의 처음으로 이동
#                 whitelisted_ips = f.read().splitlines()
                
#                 if client_ip not in whitelisted_ips:
#                     f.write(client_ip + '\n')

#             print(f"사용자 입력: {text}, IP {client_ip} added to whitelist")
#         else:
#             return "<script>alert('CAPTCHA 검증 실패!!'); history.back();</script>", 400
#     return render_template('index.html', text=text)

# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=5050, debug=True)


#################################################################################################원본
# from flask import Flask, render_template, request, redirect, url_for, session, flash
# import requests
# import pyshark
# import threading

# app = Flask(__name__)

# app.secret_key = 's3cR3tK3y!@#12345678_abcdef'

# # 비정상적인 트래픽을 감지하기 위한 딕셔너리 (IP 주소별 요청 수)
# traffic_data = {}

# # DOS 감지 임계값 (예시: 같은 IP에서 10초 이내에 100개 이상의 패킷이 오면 DOS로 판단)
# DOS_THRESHOLD = 100
# TIME_FRAME = 10  # 시간 간격 (초)

# # 패킷 캡처 함수
# def capture_packets(interface='eth0'):
#     global traffic_data
#     capture = pyshark.LiveCapture(interface=interface)
    
#     for packet in capture.sniff_continuously():
#         try:
#             src_ip = packet.ip.src
#             if src_ip in traffic_data:
#                 traffic_data[src_ip]['count'] += 1
#             else:
#                 traffic_data[src_ip] = {'count': 1, 'timestamp': packet.sniff_time}
            
#             # 동일 IP에서 일정 시간 내에 비정상적인 트래픽이 발생하면 경고
#             if traffic_data[src_ip]['count'] > DOS_THRESHOLD:
#                 flash(f"[ALERT] DOS 공격 감지: {src_ip}에서 비정상적인 트래픽 발생")  # 경고 메시지 전달
#                 traffic_data[src_ip]['count'] = 0  # 감지 후 카운트 리셋
                
#         except AttributeError:
#             # 패킷에 IP 정보가 없으면 무시 (예: ARP 패킷)
#             pass

# # Flask 앱 실행 시 백그라운드에서 패킷 캡처 실행
# @app.before_request
# def activate_packet_capture():
#     capture_thread = threading.Thread(target=capture_packets)
#     capture_thread.daemon = True  # Flask 종료 시 스레드 종료
#     capture_thread.start()

# # 기본 페이지: reCAPTCHA 인증 페이지로 리디렉션
# @app.route('/')
# def index():
#     return redirect(url_for('recaptcha'))

# # reCAPTCHA 인증 페이지
# @app.route('/recaptcha', methods=['GET', 'POST'])
# def recaptcha():
#     if request.method == 'POST':
#         captcha_response = request.form['g-recaptcha-response']
#         secret_key = '6LdtPjgqAAAAAPLNFUfhrhxMYcSzIrQUkleG0VrL'  # Google reCAPTCHA 시크릿 키
#         verify_url = 'https://www.google.com/recaptcha/api/siteverify'
#         data = {'secret': secret_key, 'response': captcha_response}
#         response = requests.post(verify_url, data=data)
#         result = response.json()

#         if result.get('success'):
#             session['authenticated'] = True  # reCAPTCHA 인증 완료를 세션에 저장
#             return redirect(url_for('main'))  # 인증 성공 시 메인 페이지로 리디렉션
#         else:
#             session['authenticated'] = False
#             return render_template('failed.html')  # 인증 실패 시 에러 페이지 표시

#     return render_template('recaptcha.html')  # GET 요청 시 reCAPTCHA 페이지 렌더링

# # 메인 페이지: reCAPTCHA 인증이 완료된 경우에만 접근 가능
# @app.route('/main')
# def main():
#     if not session.get('authenticated'):  # 세션에 인증 정보가 없으면 reCAPTCHA 페이지로 리디렉션
#         return redirect(url_for('recaptcha'))
#     return render_template('index.html')  # 인증 후에만 접근 가능한 페이지

# # 로그아웃 (선택 사항)
# @app.route('/logout')
# def logout():
#     session.pop('authenticated', None)  # 세션에서 인증 정보를 제거
#     return redirect(url_for('recaptcha'))  # 로그아웃 후 reCAPTCHA 페이지로 리디렉션

# if __name__ == '__main__':
#     app.run(host='0.0.0.0', debug=True, port=5050)


from flask import Flask, render_template, request, redirect, url_for, session, flash
import requests, pyshark, threading, time, asyncio

app = Flask(__name__)

app.secret_key = 's3cR3tK3y!@#12345678_abcdef'

# 화이트리스트 및 블랙리스트
whitelist = set()
blacklist = set()

# 패킷 카운트 저장
packet_counts = {}
packet_history = {}

# 임계값 설정
total_threshold = 1000  # 3분 동안 총 패킷 수 임계값
average_threshold = 300  # 3분 동안 평균 패킷 수 임계값
monitoring_duration = 300  # 블랙리스트 IP 모니터링 시간 (5분)

# 추가 감지 기준 (출발지 IP에 상관없이)
global_packet_count = 0  # 전체 트래픽을 모니터링
request_patterns = {}
port_traffic = {}

request_threshold = 500  # 특정 리소스에 대한 요청 수 임계값
port_threshold = 800  # 특정 포트에 대한 트래픽 임계값

# 패킷 모니터링 함수
def monitor_packets(packet):
    global global_packet_count, total_packet_count

    ip = packet.ip.src

    # 출발지 IP와 상관없이 총 패킷 수 증가
    global_packet_count += 1

    # 전체 트래픽이 임계값을 초과하는지 체크
    if global_packet_count > total_threshold:
        print(f"[경고] DDoS 공격 감지: 전체 트래픽 임계값 초과 ({global_packet_count})")

    if ip in whitelist:
        # 현재 시간
        current_time = time.time()

        # 3분 내 패킷 기록 저장 (타임스탬프와 패킷 수 기록)
        if ip not in packet_history:
            packet_history[ip] = []
        packet_history[ip].append((current_time, 1))

        # 3분 내의 패킷 기록만 유지
        packet_history[ip] = [(t, count) for t, count in packet_history[ip] if current_time - t <= 180]

        # 총량 임계값 체크 (3분 동안 받은 패킷 총량)
        total_packets = sum(count for _, count in packet_history[ip])
        if total_packets > total_threshold:
            blacklist.add(ip)
            start_monitoring_blacklisted_ip(ip)

        # 평균값 임계값 체크 (3분 동안 평균 패킷 수)
        if len(packet_history[ip]) > 0:
            avg_packets = total_packets / len(packet_history[ip])
            if avg_packets > average_threshold:
                blacklist.add(ip)
                start_monitoring_blacklisted_ip(ip)

    # 동일한 요청 URL에 대한 비정상적인 트래픽 감지
    try:
        request_url = packet.http.request_full_uri
        if request_url not in request_patterns:
            request_patterns[request_url] = 0
        request_patterns[request_url] += 1

        if request_patterns[request_url] > request_threshold:
            print(f"[경고] DDoS 공격 감지: {request_url}에 대한 비정상적인 요청 발생")
    except AttributeError:
        # HTTP 패킷이 아닌 경우 무시
        pass

    # 동일한 목적지 포트에 대한 비정상적인 트래픽 감지
    try:
        dest_port = packet.transport_layer  # 예: TCP/UDP 레이어의 포트 추출
        if dest_port not in port_traffic:
            port_traffic[dest_port] = 0
        port_traffic[dest_port] += 1

        if port_traffic[dest_port] > port_threshold:
            print(f"[경고] DDoS 공격 감지: 포트 {dest_port}에 대한 비정상적인 트래픽 발생")
    except AttributeError:
        # 트랜스포트 레이어 정보가 없는 패킷 무시
        pass

# 블랙리스트 IP 모니터링 (5분 동안 감시)
def start_monitoring_blacklisted_ip(ip):
    start_time = time.time()
    initial_packet_count = packet_counts.get(ip, 0)
    warning_issued = False

    while time.time() - start_time < monitoring_duration:
        current_packet_count = packet_counts.get(ip, 0)

        # 패킷이 계속 증가하면 경고 출력
        if current_packet_count > initial_packet_count * 1.5:
            if not warning_issued:
                print(f"[경고] {ip}에서 비정상적인 트래픽 발생!")
                warning_issued = True

        # 10분 동안 지속되면 DDoS 감지
        if time.time() - start_time >= 600:
            print(f"[알림] DDoS 공격 감지 - {ip}")
            break

        time.sleep(1)

# 패킷 캡처 함수
last_attack_time = time.time()  # 마지막 공격 감지 시간
attack_pause_duration = 60  # 1분 동안 공격이 없으면 메시지 출력 멈춤

def capture_packets(interface='Wi-Fi'):
    global last_attack_time  # 전역 변수로 선언

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    server_ip = '182.230.182.141'
    capture = pyshark.LiveCapture(interface=interface, display_filter=f'ip.dst == {server_ip} && tcp.port == 1234')

    
    capture.sniff_continuously()
    for packet in capture.sniff_continuously():
        try:
            src_ip = packet.ip.src
            current_time = time.time()

            # 마지막 공격 이후 일정 시간이 지나면 출력 멈춤
            if current_time - last_attack_time > attack_pause_duration:
                continue

            print(f"Packet from IP: {src_ip} to {server_ip}")
            
            # DDoS 감지 로직 수행
            monitor_packets(packet)

            # 공격이 감지되었을 때 시간 기록
            if is_ddos_attack():
                last_attack_time = current_time  # 마지막 공격 시간 업데이트
        except AttributeError:
            pass

def is_ddos_attack():
    # 패킷 모니터링 상태에 따라 DDoS 공격 여부를 판단
    # 예시로 특정 조건을 만족하면 True 반환 (실제 로직 추가 필요)
    if global_packet_count > total_threshold:
        return True
    return False

# Flask 앱 실행 시 백그라운드에서 패킷 캡처 실행
@app.before_request
def activate_packet_capture():
    capture_thread = threading.Thread(target=capture_packets)
    capture_thread.daemon = True  # Flask 종료 시 스레드 종료
    capture_thread.start()

# 기본 페이지: reCAPTCHA 인증 페이지로 리디렉션
@app.route('/')
def index():
    return redirect(url_for('recaptcha'))

# reCAPTCHA 인증 페이지
@app.route('/recaptcha', methods=['GET', 'POST'])
def recaptcha():
    if request.method == 'POST':
        captcha_response = request.form['g-recaptcha-response']
        secret_key = '6LdtPjgqAAAAAPLNFUfhrhxMYcSzIrQUkleG0VrL'  # Google reCAPTCHA 시크릿 키
        verify_url = 'https://www.google.com/recaptcha/api/siteverify'
        data = {'secret': secret_key, 'response': captcha_response}
        response = requests.post(verify_url, data=data)
        result = response.json()

        if result.get('success'):
            session['authenticated'] = True  # reCAPTCHA 인증 완료를 세션에 저장
            whitelist.add(request.remote_addr)  # 인증된 IP를 화이트리스트에 추가
            return redirect(url_for('main'))  # 인증 성공 시 메인 페이지로 리디렉션
        else:
            session['authenticated'] = False
            return render_template('failed.html')  # 인증 실패 시 에러 페이지 표시

    return render_template('recaptcha.html')  # GET 요청 시 reCAPTCHA 페이지 렌더링

# 메인 페이지: reCAPTCHA 인증이 완료된 경우에만 접근 가능
@app.route('/main')
def main():
    if not session.get('authenticated'):  # 세션에 인증 정보가 없으면 reCAPTCHA 페이지로 리디렉션
        return redirect(url_for('recaptcha'))
    return render_template('index.html')  # 인증 후에만 접근 가능한 페이지

# 로그아웃 (선택 사항)
@app.route('/logout')
def logout():
    session.pop('authenticated', None)  # 세션에서 인증 정보를 제거
    return redirect(url_for('recaptcha'))  # 로그아웃 후 reCAPTCHA 페이지로 리디렉션

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5050)