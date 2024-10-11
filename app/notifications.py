from pushbullet import PushBullet
from dotenv import load_dotenv
import os

def send_msg(text, atck):
    load_dotenv()

    API_KEY = os.getenv('API_KEY')

    try:
        # PushBullet API 사용
        pb = PushBullet(API_KEY)

        # 등록된 디바이스 확인
        devices = pb.devices

        # 푸시 알림 전송
        # push = pb.push_file(device=devices[0], file_url='C:\\Users\\12000\\Downloads\\pushbullet\\team-386673_1280.jpg', file_name='트래픽 그래프', file_type='image')
        pb.push_note(f"서버 트래픽 알림 : {atck}", text)
        print('푸시 알림 전송 성공')
    except Exception as e:
        print(f'푸시 알림 전송 실패: {e}')