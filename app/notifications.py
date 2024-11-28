from pushbullet import PushBullet
from dotenv import load_dotenv
import os

def send_msg(text):
    load_dotenv()

    API_KEY = os.getenv('API_KEY')

    try:
        # PushBullet API 사용
        pb = PushBullet(API_KEY)

        emails = ['20191911@edu.hanbat.ac.kr', 'tmdwns2941@gmail.com']
        for email in emails:
            pb.push_note("서버 트래픽 알림 [DDoS]", text, email=email)
        print('푸시 알림 전송 성공')
    except Exception as e:
        print(f'푸시 알림 전송 실패: {e}')