from twilio.rest import Client

account_sid = 'ACfbeef8c50838c40766d24479947a106a'
auth_token = 'dff00c52e9c4469055219720b0f788ad'
client = Client(account_sid, auth_token)

message = client.messages.create(
  from_='+19045744303',
  body='''
[경고]DDoS 공격 감지
서버 확인 요망
''',
  to='+821041272507'
)

print(message.sid)