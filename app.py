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

from flask import Flask, render_template, request, redirect, url_for, session, flash
import requests
import pyshark
import threading
import time

app = Flask(__name__)

app.secret_key = 's3cR3tK3y!@#12345678_abcdef'

# DoS 공격 감지 기준
total_threshold = 1000  # 3분 동안 총 패킷 수 임계값
average_threshold = 300  # 3분 동안 평균 패킷 수 임계값
monitoring_duration = 180  # 3분 동안 모니터링

# 패킷 모니터링 함수
def monitor_packets():
    capture = pyshark.LiveCapture(interface='Wi-Fi')  # 적절한 인터페이스로 수정 필요
    packet_count = 0
    packet_timestamps = []

    while True:
        for packet in capture.sniff_continuously(packet_count=10):
            current_time = time.time()
            packet_timestamps.append(current_time)
            packet_count += 1

            # 3분 내 패킷 수 계산
            packet_timestamps = [timestamp for timestamp in packet_timestamps if current_time - timestamp <= monitoring_duration]
            total_packets = len(packet_timestamps)

            # 3분 동안 총 패킷 수가 임계값을 넘는 경우
            if total_packets > total_threshold:
                session['dos_attack'] = True  # DoS 공격 상태 저장
                print(f"[경고] 총 패킷 수 초과: {total_packets}개 패킷")
            
            # 3분 동안 평균 패킷 수가 임계값을 넘는 경우
            if len(packet_timestamps) > 0:
                avg_packets = total_packets / len(packet_timestamps)
                if avg_packets > average_threshold:
                    session['dos_attack'] = True  # DoS 공격 상태 저장
                    print(f"[경고] 평균 패킷 수 초과: {avg_packets}개 패킷/초")

        time.sleep(1)

# DoS 공격 감지 여부를 클라이언트에 전달하는 함수
def check_dos_attack():
    return session.get('dos_attack', False)

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
            session['dos_attack'] = False  # 공격 상태 초기화
            return redirect(url_for('main'))  # 인증 성공 시 메인 페이지로 리디렉션
        else:
            session['authenticated'] = False
            return "<script>alert('캡차 인증 실패'); history.back();</script>"

    return render_template('recaptcha.html')  # GET 요청 시 reCAPTCHA 페이지 렌더링

# 메인 페이지: reCAPTCHA 인증이 완료된 경우에만 접근 가능
@app.route('/main')
def main():
    if not session.get('authenticated'):  # 세션에 인증 정보가 없으면 reCAPTCHA 페이지로 리디렉션
        return redirect(url_for('recaptcha'))
    
    if check_dos_attack():  # DoS 공격 감지 시 경고 메시지 표시
        return "<script>alert('DoS 공격 감지! 경고!');</script>" + render_template('index.html')
    
    return render_template('index.html')  # 인증 후에만 접근 가능한 페이지

# 로그아웃 (선택 사항)
@app.route('/logout')
def logout():
    session.pop('authenticated', None)  # 세션에서 인증 정보를 제거
    return redirect(url_for('recaptcha'))  # 로그아웃 후 reCAPTCHA 페이지로 리디렉션

if __name__ == '__main__':
    # 패킷 감지 스레드 실행
    packet_monitor_thread = threading.Thread(target=monitor_packets)
    packet_monitor_thread.daemon = True  # Flask 종료 시 스레드 종료
    packet_monitor_thread.start()
    
    app.run(host='0.0.0.0', debug=True, port=5050)