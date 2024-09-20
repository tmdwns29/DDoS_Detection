# from locust import HttpUser, task, between

# class UserBehavior(HttpUser):
#     wait_time = between(1, 5) #  작업 사이 1초에서 5초 사이의 랜덤 대기 시간 지정

#     @task
#     def index(self):
#         self.client.get("/") # 주소 url에 GET 요청 전송