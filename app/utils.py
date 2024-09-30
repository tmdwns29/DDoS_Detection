import requests

def verify_recaptcha(captcha_response):
    secret_key = '6LdtPjgqAAAAAPLNFUfhrhxMYcSzIrQUkleG0VrL'
    verify_url = 'https://www.google.com/recaptcha/api/siteverify'
    data = {'secret': secret_key, 'response': captcha_response}
    response = requests.post(verify_url, data=data)
    result = response.json()
    return result.get('success')