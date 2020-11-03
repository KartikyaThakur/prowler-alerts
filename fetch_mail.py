import imaplib
import email
from email.header import decode_header
import webbrowser
import os
from mail_config import config
from prowler_alert_processor import ProwlerAlertProcessor
from pandas import *
import xlwt 
from xlwt import Workbook 
import xlrd
from datetime import date
import re

def main():
    username = config['username']
    password = config['password']
    imap = imaplib.IMAP4_SSL('imap.outlook.com')
    imap.login(username, password)
    status, messages = imap.select(config['mailbox'])
    type, data = imap.search(None, '(SENTSINCE "20-Oct-2020")')

    loop_cnt = 0

    for num in data[0].split():
        loop_cnt = loop_cnt + 1
        rv, data = imap.fetch(num, '(RFC822)')
        if rv != 'OK':
            print("ERROR getting message", num)
            
        raw_email = data[0][1].decode("utf-8")
        email_messages = email.message_from_string(raw_email)
        if email_messages.is_multipart():
            for email_message in email_messages.get_payload():
                email_body = email_message.get_payload()
                write_email_to_file(num, email_body)
        else:
            email_body = email_messages.get_payload()
            write_email_to_file(num, email_body)

def write_email_to_file(filename, email_body):
    with open('./emails/'+filename+'.txt', 'w') as file:
        file.write(email_body)

main()