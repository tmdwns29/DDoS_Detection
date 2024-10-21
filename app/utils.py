import requests
from dotenv import load_dotenv
import os

load_dotenv()

def verify_recaptcha(captcha_response):
    secret_key = os.getenv('CAPTCHA_SECRET_KEY')
    verify_url = 'https://www.google.com/recaptcha/api/siteverify'
    data = {'secret': secret_key, 'response': captcha_response}
    response = requests.post(verify_url, data=data)
    result = response.json()
    return result.get('success')