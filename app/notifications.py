from pushbullet import PushBullet
from dotenv import load_dotenv
import os

def send_msg(text, atck):
    load_dotenv()

    API_KEY = os.getenv('API_KEY')

    try:
        # PushBullet API 사용
        pb = PushBullet(API_KEY)

        pb.push_note(f"서버 트래픽 알림 [DDoS]", text)
        print('푸시 알림 전송 성공')
    except Exception as e:
        print(f'푸시 알림 전송 실패: {e}')