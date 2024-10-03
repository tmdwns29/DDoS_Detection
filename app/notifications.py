from pushbullet import PushBullet

def send_msg(text):
    API_KEY = "o.j7rSYqAr9ldk6zqJwofUe1azpC07E3la"
    file = "C:\\Users\\12000\\captcha_website\\DDoS_Detection\\resolution.txt"

    # PushBullet API 사용
    pb = PushBullet(API_KEY)

    # 등록된 디바이스 확인
    devices = pb.devices

    # 푸시 알림 전송
    # push = pb.push_file(device=devices[0], file_url='C:\\Users\\12000\\Downloads\\pushbullet\\team-386673_1280.jpg', file_name='트래픽 그래프', file_type='image')
    pb.push_note("트래픽 이상 감지 시스템", text)