# 기존의 Python 베이스 이미지 설정
FROM python:3.12-slim

# 필요한 시스템 패키지 설치 (tshark 포함)
RUN apt-get update && apt-get install -y \
    tshark \
    && rm -rf /var/lib/apt/lists/*

# 필요한 파이썬 패키지 설치
COPY requirements.txt .
RUN pip install -r requirements.txt

# 앱 소스 복사
COPY . /app
WORKDIR /app

# 환경변수 설정 (필요시)
ENV PATH="$PATH:/usr/bin/tshark"

# Flask 앱 실행 (또는 Gunicorn)
CMD ["gunicorn", "-b", "0.0.0.0:5050", "app:app"]