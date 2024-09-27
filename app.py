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


################################################################################################원본
# from flask import Flask, render_template, request, redirect, url_for, session, flash
# import requests
# import pyshark
# import threading
# import time

# app = Flask(__name__)

# app.secret_key = 's3cR3tK3y!@#12345678_abcdef'

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
#             return "<script>alert('캡차 인증 실패'); history.back();</script>"

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

# import asyncio
# import pyshark
# import threading
# import time
# import requests
# import sys
# from flask import Flask, render_template, request, redirect, url_for, session, flash
# from scapy.all import wrpcap, Ether
# from scapy.config import conf
# from datetime import datetime

# conf.prog.tshark = "C:\\Program Files\\Wireshark\\tshark.exe"

# app = Flask(__name__)

# app.secret_key = 's3cR3tK3y!@#12345678_abcdef'

# # 패킷 모니터링 플래그
# attack_detected = False

# # 기본 페이지: reCAPTCHA 인증 페이지로 리디렉션
# @app.route('/')
# def index():
#     return redirect(url_for('recaptcha'))

# # reCAPTCHA 인증 페이지
# @app.route('/recaptcha', methods=['GET', 'POST'])
# def recaptcha():
#     if attack_detected:
#         flash('DDoS 공격이 감지되었습니다! 즉시 조치가 필요합니다.', 'danger')
    
#     if request.method == 'POST':
#         captcha_response = request.form['g-recaptcha-response']
#         secret_key = '6LdtPjgqAAAAAPLNFUfhrhxMYcSzIrQUkleG0VrL'  # Google reCAPTCHA 시크릿 키
#         verify_url = 'https://www.google.com/recaptcha/api/siteverify'
#         data = {'secret': secret_key, 'response': captcha_response}
#         response = requests.post(verify_url, data=data)
#         result = response.json()

#         if result.get('success'):
#             session['authenticated'] = True  # reCAPTCHA 인증 완료를 세션에 저장
#             start_packet_monitoring()  # 인증 후 패킷 모니터링 시작
#             return redirect(url_for('main'))  # 인증 성공 시 메인 페이지로 리디렉션
#         else:
#             session['authenticated'] = False
#             return "<script>alert('캡차 인증 실패'); history.back();</script>"

#     return render_template('recaptcha.html')  # GET 요청 시 reCAPTCHA 페이지 렌더링

# # 메인 페이지: reCAPTCHA 인증이 완료된 경우에만 접근 가능
# @app.route('/main')
# def main():
#     if not session.get('authenticated'):  # 세션에 인증 정보가 없으면 reCAPTCHA 페이지로 리디렉션
#         return redirect(url_for('recaptcha'))
    
#     if attack_detected:  # 패킷 감지가 일정 횟수 이상 발생한 경우
#         flash('DDoS 공격 감지됨! 즉시 조치가 필요합니다.', 'danger')
#         return redirect(url_for('recaptcha'))
    
#     return render_template('index.html')  # 인증 후에만 접근 가능한 페이지

# # 로그아웃 (선택 사항)
# @app.route('/logout')
# def logout():
#     session.pop('authenticated', None)  # 세션에서 인증 정보를 제거
#     return redirect(url_for('recaptcha'))  # 로그아웃 후 reCAPTCHA 페이지로 리디렉션

# def monitor_packets():
#     global attack_detected

#     try:
#         loop = asyncio.new_event_loop()
#         asyncio.set_event_loop(loop)

#         interface = 'Wi-Fi'

#         # TCP SYN FLOODING이 의심되는 패킷의 특징 적용
#         capture = pyshark.LiveCapture(interface=interface,
#                                       display_filter="tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.dstport == 21 && tcp.analysis.retransmission",
#                                       include_raw=True,
#                                       use_json=True)

#         total_threshold = 1000
#         average_threshold = 300
#         packet_count = 0

#         unix_start_time = time.time()
#         start_time = datetime.fromtimestamp(unix_start_time).strftime('%Y-%m-%d %H:%M:%S')
#         print(f"모니터링 시작 시간: {start_time}")
#         sys.stdout.flush()

#         # captured_packets = []  # 추출된 패킷을 저장할 리스트

#         for packet in capture.sniff_continuously():
#             packet_count += 1
#             elapsed_time = time.time() - unix_start_time
#             print("경과 시간: %.1f sec"%elapsed_time)
#             print(attack_detected)
#             sys.stdout.flush()

#             # 패킷을 Scapy의 Ether 객체로 변환하여 저장
#             # raw_packet = bytes.fromhex(packet.frame_raw.value)
#             # captured_packets.append(Ether(raw_packet))

#             # if len(captured_packets) >= 100:  # 100개의 패킷을 저장하면 중지
#             #     wrpcap('captured_packets.pcapng', captured_packets)  # 패킷을 pcapng 파일로 저장
#             #     print(f"100개의 패킷을 'captured_packets.pcapng' 파일로 저장했습니다.")

#             if elapsed_time >= 180:
#                 avg_packets_per_second = packet_count / elapsed_time

#                 if packet_count >= total_threshold or avg_packets_per_second >= average_threshold:
#                     attack_detected = True
#                     print(f"DDoS 공격 감지! 총 패킷 수: {packet_count}, 초당 평균 패킷 수: {avg_packets_per_second}")
#                     sys.stdout.flush()
#                     break
#                 else:
#                     attack_detected = False

#     except Exception as e:
#         print(f"오류 발생: {e}")
#         sys.stdout.flush()

# # 패킷 모니터링 함수
# def start_packet_monitoring():
#     try:
#         monitoring_thread = threading.Thread(target=monitor_packets)
#         monitoring_thread.daemon = True
#         monitoring_thread.start()
#     except Exception as e:
#         print(f"스레드 오류: {e}")
#         sys.stdout.flush()

# # Flask 앱 실행
# if __name__ == '__main__':
#     start_packet_monitoring()  # 서버 시작 시 패킷 모니터링 시작
#     app.run(host='0.0.0.0', port=5050, debug=False)  # Flask 서버 실행

import asyncio
import pyshark
import threading
import time
import requests
import sys
from twilio.rest import Client
from flask import Flask, render_template, request, redirect, url_for, session, flash
from scapy.config import conf
from datetime import datetime

conf.prog.tshark = "C:\\Program Files\\Wireshark\\tshark.exe"

app = Flask(__name__)

app.secret_key = 's3cR3tK3y!@#12345678_abcdef'

# 패킷 모니터링 플래그
attack_detected = False
last_attack_time = None  # 마지막 공격 감지 시간 기록
sms_bool = False

# 기본 페이지: reCAPTCHA 인증 페이지로 리디렉션
@app.route('/')
def index():
    return redirect(url_for('recaptcha'))

# reCAPTCHA 인증 페이지
@app.route('/recaptcha', methods=['GET', 'POST'])
def recaptcha():
    global attack_detected
    global last_attack_time
    global sms_bool

    # 공격이 감지되면 경고 알림 표시
    if attack_detected:
        flash('DDoS 공격이 감지되었습니다! 즉시 조치가 필요합니다.', 'danger')
        if not sms_bool:
            SMS_notification(f"""\nDDoS공격 감지! 확인바랍니다\n[갸라DOS]""")
            sms_bool = True

    # 공격이 감지된 후 일정 시간 동안 공격 패킷이 더 이상 감지되지 않으면 공격이 중지된 것으로 판단
    if last_attack_time and time.time() - last_attack_time > 60:  # 60초 동안 추가 공격이 없으면 중지로 판단
        attack_detected = False
        sms_bool = False

    if request.method == 'POST':
        captcha_response = request.form['g-recaptcha-response']
        secret_key = '6LdtPjgqAAAAAPLNFUfhrhxMYcSzIrQUkleG0VrL'  # Google reCAPTCHA 시크릿 키
        verify_url = 'https://www.google.com/recaptcha/api/siteverify'
        data = {'secret': secret_key, 'response': captcha_response}
        response = requests.post(verify_url, data=data)
        result = response.json()

        if result.get('success'):
            session['authenticated'] = True  # reCAPTCHA 인증 완료를 세션에 저장
            return redirect(url_for('main'))  # 인증 성공 시 메인 페이지로 리디렉션
        else:
            session['authenticated'] = False
            return "<script>alert('캡차 인증 실패'); history.back();</script>"

    return render_template('recaptcha.html')  # GET 요청 시 reCAPTCHA 페이지 렌더링

# 메인 페이지: reCAPTCHA 인증이 완료된 경우에만 접근 가능
@app.route('/main')
def main():
    global attack_detected

    if not session.get('authenticated'):  # 세션에 인증 정보가 없으면 reCAPTCHA 페이지로 리디렉션
        return redirect(url_for('recaptcha'))
    
    # 공격이 감지되면 경고 알림 표시
    if attack_detected:
        flash('DDoS 공격이 감지되었습니다! 즉시 조치가 필요합니다.', 'danger')
        return redirect(url_for('recaptcha'))
    
    return render_template('index.html')  # 인증 후에만 접근 가능한 페이지

# 로그아웃 (선택 사항)
@app.route('/logout')
def logout():
    session.pop('authenticated', None)  # 세션에서 인증 정보를 제거
    return redirect(url_for('recaptcha'))  # 로그아웃 후 reCAPTCHA 페이지로 리디렉션

def monitor_packets():
    global attack_detected
    global last_attack_time

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        interface = 'Wi-Fi'

        capture = pyshark.LiveCapture(interface=interface,
                                      display_filter="tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.dstport == 21 && tcp.analysis.retransmission",
                                      include_raw=True,
                                      use_json=True)

        total_threshold = 1000
        average_threshold = 300
        packet_count = 0

        while True:
            unix_start_time = time.time()
            start_time = datetime.fromtimestamp(unix_start_time).strftime('%Y-%m-%d %H:%M:%S')
            print(f"모니터링 시작 시간: {start_time}")
            sys.stdout.flush()

            for packet in capture.sniff_continuously():
                packet_count += 1
                elapsed_time = time.time() - unix_start_time
                print(f"경과 시간: {elapsed_time:.4f} sec, 총 패킷 수: {packet_count}")
                sys.stdout.flush()

                if elapsed_time >= 60:
                    avg_packets_per_second = packet_count / elapsed_time

                    if packet_count >= total_threshold:
                        # TODO : 1차 필터 3분 총 패킷 감지 경고
                        if avg_packets_per_second >= average_threshold:
                            # 2차 필터 -> 5분 초당 평균 패킷 감지 경고
                            # 3차 필터 -> 7분 초당 평균 패킷 감지 경고
                            attack_detected = True
                            last_attack_time = time.time()  # 마지막 공격 시간 기록
                            print(f"DDoS 공격 감지! 총 패킷 수: {packet_count}, 초당 평균 패킷 수: {avg_packets_per_second}")
                            sys.stdout.flush()
                        break
                    else:
                        last_attack_time = time.time()  # 마지막 공격 시간 기록
            
            # 패킷 모니터링 재시작을 위한 준비 (임계값 초기화 등)
            print("3분 대기 후 패킷 모니터링 재시작")
            time.sleep(5)  # 3분(180초) 대기 후 다시 패킷 모니터링
            sys.stdout.flush()

    except Exception as e:
        print(f"오류 발생: {e}")
        sys.stdout.flush()

# 패킷 모니터링 함수
def start_packet_monitoring():
    try:
        monitoring_thread = threading.Thread(target=monitor_packets)
        monitoring_thread.daemon = True
        monitoring_thread.start()
    except Exception as e:
        print(f"스레드 오류: {e}")
        sys.stdout.flush()

def SMS_notification(contents):
    account_sid = 'ACfbeef8c50838c40766d24479947a106a'
    auth_token = 'dff00c52e9c4469055219720b0f788ad'
    client = Client(account_sid, auth_token)

    message = client.messages.create(
        from_='+19045744303',
        body = contents,
        to='+821041272507'
    )
    print(message.sid)


def measure_rps(url, duration=10):
    """
    주어진 URL로 초당 요청 수(RPS)를 측정하는 함수.
    
    Parameters:
    url (str): 요청할 URL
    duration (int): 테스트 지속 시간 (초)
    
    Returns:
    float: 측정된 초당 요청 수 (RPS)
    """
    start_time = time.time()
    request_count = 0
    
    while True:
        current_time = time.time()
        if current_time - start_time > duration:
            break
        
        # HTTP 요청 보내기
        response = requests.get(url)
        
        # 요청 성공 시 카운트 증가
        if response.status_code == 200:
            request_count += 1
    
    # 총 걸린 시간 계산
    elapsed_time = time.time() - start_time
    
    # RPS 계산
    rps = request_count / elapsed_time
    return rps

# Flask와 wxPython을 각각 다른 스레드에서 실행
if __name__ == '__main__':
    start_packet_monitoring()
    app.run(host='0.0.0.0', port=5050, debug=False)