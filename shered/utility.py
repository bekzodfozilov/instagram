import re
import threading
from multiprocessing.connection import Client

from decouple import config
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from rest_framework.exceptions import ValidationError


email_regex = r'[^@ \t\r\n]+@[^@ \t\r\n]+\.[^@ \t\r\n]+'
phone_regex = r'^[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}$'
username_regex = r"^[a-zA-Z0-9](?:[a-zA-Z0-9_]{1,18}[a-zA-Z0-9])?$"


def check_email_or_phone(email_or_phone):

    if re.fullmatch(email_regex, email_or_phone):
        email_or_phone = "email"

    elif re.fullmatch(phone_regex, email_or_phone):
        email_or_phone = 'phone'

    else:
        data = {
            "success": False,
            "message": "Email yoki telefon raqamingiz notogri"
        }
        raise ValidationError(data)

    return email_or_phone

def check_user_type(userinput):
    if re.fullmatch(email_regex, userinput):
        userinput = "email"
    elif re.fullmatch(phone_regex, userinput):
        userinput = "phone"
    elif re.fullmatch(username_regex, userinput):
        userinput = "username"
    else:
        raise ValidationError({
            "success": False,
            "message": "Username, email yoki telefon number xato"
        })

    return userinput





class EmailThread(threading.Thread):

    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send()


class Email:
    @staticmethod
    def send_email(data):
        email = EmailMessage(
            subject=data['subject'],
            body=data['body'],
            to=[data['to_email']]
        )
        if data.get('content_type') == "html":
            email.content_subtype = 'html'
        EmailThread(email).start()


def send_email(email, code):
    html_content = render_to_string(
        'email/authentication/activate_account.html',
        {"code": code}
    )
    Email.send_email(
        {
            "subject": "Royhatdan otish",
            "to_email": email,
            "body": html_content,
            "content_type": "html"
        }
    )

def send_phone_code(phone, code):
    account_sid = config('account_sid')
    auth_token = config('auth_token')
    client = Client(account_sid, auth_token)
    client.message.create(
        body=f'Salom sizning tastiqlash codingiz {code}',
        from_='+998998090816',
        to=f'{phone}'
    )