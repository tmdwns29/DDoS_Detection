from twilio.rest import Client

class SMSNotification:
    def __init__(self):
        self.account_sid = 'ACfbeef8c50838c40766d24479947a106a'
        self.auth_token = 'dff00c52e9c4469055219720b0f788ad'
        self.client = Client(self.account_sid, self.auth_token)

    def send_sms(self, contents, to_number='+821041272507'):
        message = self.client.messages.create(
            from_='+19045744303',
            body=contents,
            to=to_number
        )
        print(message.sid)

# from twilio.rest import Client

# account_sid = 'ACfbeef8c50838c40766d24479947a106a'
# auth_token = 'dff00c52e9c4469055219720b0f788ad'
# client = Client(account_sid, auth_token)

# message = client.messages.create(
#   from_='+19045744303',
#   body='''
# [경고]DDoS 공격 감지
# 서버 확인 요망
# ''',
#   to='+821041272507'
# )

# print(message.sid)