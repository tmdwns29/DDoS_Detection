from flask import Flask, session
from app.routes import main_routes  # Flask 라우트 임포트
from app.monitoring import packet_monitor  # PacketMonitor 임포트
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')
app.register_blueprint(main_routes)

if __name__ == '__main__':
    # 패킷 모니터링 스레드 시작
    packet_monitor.start_monitoring()
    app.run(host='0.0.0.0', port=5050, debug=False)