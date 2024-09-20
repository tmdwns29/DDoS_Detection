from flask import Flask, render_template, request
import time, os, requests

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


from flask import Flask, render_template, request, redirect, url_for, make_response
import time, os, requests, uuid

app = Flask(__name__)

whitelist_file = 'whitelist.txt'

@app.route('/', methods=['GET', 'POST'])
def home():
    text = None
    if request.method == 'POST':
        captcha_response = request.form['g-recaptcha-response']
        secret_key = '6LdUUkkqAAAAAA6vCu__hLaamUUoQMluJc4qy9y0'
        verify_url = 'https://www.google.com/recaptcha/api/siteverify'
        data = {'secret': secret_key, 'response': captcha_response}
        response = requests.post(verify_url, data=data)
        result = response.json()

        if result.get('success'):
            text = request.form['user_input']
            client_ip = request.remote_addr

            # Add the client IP to the whitelist file
            with open(whitelist_file, 'a+') as f:
                f.seek(0)  # 파일의 처음으로 이동
                whitelisted_ips = f.read().splitlines()
                
                if client_ip not in whitelisted_ips:
                    f.write(client_ip + '\n')

            print(f"사용자 입력: {text}, IP {client_ip} added to whitelist")
        else:
            return "<script>alert('CAPTCHA 검증 실패!!'); history.back();</script>", 400
    return render_template('index.html', text=text)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050, debug=True)
