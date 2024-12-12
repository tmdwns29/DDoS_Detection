# 국립한밭대학교 갸라DOS팀

## 주제 
- 트래픽변화량을 이용한 DDoS 공격 탐지 프로그램 
  
## 팀 구성 
- 20191893 김강식 정보통신공학과
- 20191911 유승준 정보통신공학과
- 20191918 임동건 정보통신공학과

## Project Background
  - ### 개요
    - 사회적 문제로 대두되는 DDoS공격의 심각성 재고
    - 캡차 인증을 통한 악성 Bot 필터링
    - 트래픽변화량을 이용하여 SYN Flooding, UDP Flooding, Ping of Death 공격을 실시간 탐지
  - ### 필요성
    - 실시간 네트워크 트래픽 모니터링을 통해 DDoS공격을 조기에 탐지
    - 여러 알림 기능을 통해 사용자에게 탐지 내용을 즉각적으로 알림
    - 악의적인 Bot을 차단함으로써 웹 서버 보안 강화
    
## 프로젝트 내용
![image](https://github.com/user-attachments/assets/869ba6c4-e5de-4517-abab-2ee050ba511e)
![image](https://github.com/user-attachments/assets/b158b4e3-a711-4777-98f5-5ba5d9406303)
![image](https://github.com/user-attachments/assets/59622442-d836-4909-b2ef-f5d6c237df30)


  - ### 구현 내용
    - 공격 패킷 캡처 필터 조건 적용
    - DDoS 공격 트래픽 임계치 설정
    - Recaptcha 봇 필터링
    - 모바일/PC 공격 감지 알림
  - ### 기대 효과
    - 실시간 DDoS 공격 탐지를 통해 웹 애플리케이션 서버의 가용성 향상
    - 관리자에게 네트워크 상태를 실시간으로 제공하여 빠르게 대응할 수 있도록 지원
    - 공격 패턴에 대한 데이터 수집을 통해 향후 DDoS 공격에 대비할 수 있는 능력 강화

## 개발환경
  - ### 개발 언어 : Python
  - ### 텍스트 에디터 : VScode
  - ### 가상화 소프트웨어 : VM ware
  - ### 운영체제
    - 공격자 : Kali Linux
    - 희생자 : Window 11
