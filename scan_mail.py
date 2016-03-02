#!/usr/bin/env python2.7
# -*- coding : utf-8 -*-

import argparse
import os
import email
import imaplib
import smtplib
import sys
import time

import ConfigParser
import StringIO

from email.header import Header, decode_header
from email.mime.text import MIMEText
from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML

def load_config_file(config_file):

    with open(config_file) as f:
        file_content = "[root]\n"
        file_content += f.read()
    content_str_fp = StringIO.StringIO(file_content)
    config = ConfigParser.RawConfigParser()
    config.readfp(content_str_fp)
    return (config.get('root', 'smtp_server'),
            config.get('root', 'imap_server'),
            config.get('root', 'username'),
            config.get('root', 'password')
    )

def get_user_info():

    return load_config_file('config')

class IMAPClient(object):

    def __init__(self, imap_server, username, password, ssl=True):

        self._mailbox = "INBOX"
        self._imap = (imaplib.IMAP4_SSL if ssl else imaplib.IMAP4)(imap_server)
        # TODO: handle the case when response is 'NO'
        self._imap.login(username, password)
        self._imap.select(self._mailbox) # default selecting the mailbox 'INBOX'

    def list_mail_box(self):

        self._imap.list()

    def _refresh_mailbox(self):
        """
            use close() and select() to force mailbox refresh.
        """

        # TODO: this is nasty, should find another way to refresh mailbox
        self._imap.close()
        self._imap.select(self._mailbox)

    def search_mail_uids(self, critirium):

        self._refresh_mailbox()
        result, data = self._imap.uid('search', None, critirium)
        return map(int, data[0].split(' '))

    def peek_mail(self, uid):

        # peek doesnt' add the flag \\SEEN
        result, data = self._imap.uid('fetch', uid, "(BODY.PEEK[])")
        raw_mail = data[0][1]
        mail = Email(uid, raw_mail)
        return mail

    def fetch_mail(self, uid):

        result, data = self._imap.uid('fetch', uid, "(RFC822)")
        raw_mail = data[0][1]
        mail = Email(uid, raw_mail)
        return mail

    def mark_mail_as_unread(self, uid):

        self._imap.uid('STORE', uid, '-FLAGS', '\\SEEN')

    def check_mail(self, mail):

        files = mail.get_attached_files()

        suspicious_files = []
        for the_file in files:
            if the_file.is_suspicious():
                suspicious_files.append(the_file.get_filename())
        if len(suspicious_files) != 0:
            message = "Mail (uid=%d) contains suspicious files\n" % mail.get_uid()
            message += '=' * len(message) + '\n'
            for filename in suspicious_files:
                message += '\t%s' % filename
        return len(suspicious_files) != 0

    def scan_all_mails(self):

        contains_suspicious_mail = False
        for uid in self.search_mail_uids('ALL'):
            mail = self.peek_mail(uid)
            mail_is_suspicious = self.check_mail(mail)
            contains_suspicious_mail |= mail_is_suspicious
        if not contains_suspicious_mail:
            print "\nCongrats! There is no suspicious mail in your mailbox!\n"

    def monitor_new_mails(self, timeout=3600):

        last_mail_uids = self.search_mail_uids('ALL')
        last_largest_mail_uid = 0 if len(last_mail_uids) == 0 else last_mail_uids[-1]
        start_time = time.time()
        print "\nWaiting for new mails ...\n"
        while time.time() - start_time < timeout:
            # fetch new mails
            now_mail_uids = self.search_mail_uids('ALL')
            now_largest_mail_uid = 0 if len(now_mail_uids) == 0 else now_mail_uids[-1]
            if now_largest_mail_uid > last_largest_mail_uid:
                for uid in now_mail_uids:
                    if uid > last_largest_mail_uid:
                        mail = self.peek_mail(uid)
                        print "[New mail] " + mail.get_subject() + "... scanning",
                        result = self.check_mail(mail)
                        print " ... " + ("suspicious" if result else "safe")
                        if result:
                            reply(mail.get_sender[1])
            last_largest_mail_uid = now_largest_mail_uid
            time.sleep(10)

    def __del__(self):

        self._imap.close() # close the selected mailbox
        self._imap.logout()


class Email(object):

    def __init__(self, uid, rfc822_mail_string):

        self._uid = uid
        self._rfc822 = rfc822_mail_string
        self._message = email.message_from_string(rfc822_mail_string)

    def get_uid(self):

        return self._uid

    def get_message(self):

        return self._message

    def get_sender(self):

        sender_name, sender_email = email.utils.parseaddr(self._message['From'])
        return sender_name, sender_email

    def get_subject(self):

        subject, charset = decode_header(self._message['SUBJECT'])[0]
        # if there is a special charset, decode it back to unicode
        if charset:
            subject = subject.decode(charset)
        return subject

    def get_attached_files(self):
        """
            return list of tupe (filename, file_content, Email objects)
        """

        files = []
        for part in self._message.walk():
            if is_ole_file(part):
                files.append(FileMessage(part, self._message))
        return files


class FileMessage(object):
    """
        this class is used to handle the email.message.Message type attached
        files.
    """

    def __init__(self, file_message, mail_message):

        self._file_message = file_message
        self._mail_message = mail_message

    def get_mail_message(self):

        return self._mail_message

    def get_file_content(self):

        return self._file_message.get_payload(decode=True)

    def get_filename(self):

        filename, charset = decode_header(self._file_message.get_filename())[0]
        if charset:
            filename = filename.decode(charset)
        return filename

    def is_suspicious(self):

        filename = self.get_filename()
        file_content = self.get_file_content()
        return is_suspicious(filename, file_content)


def is_suspicious(filename, file_content):

    vba_types = ['AutoExec', 'Suspicious', 'IOC',
                 'Hex String','Base64 String', 'Dridex String',
                 'VBA obfuscated Strings'
    ]
    vba_suspicious_type = vba_types[:3]
    vbaparser = VBA_Parser(filename, file_content)

    if not vbaparser.detect_vba_macros():
        return False
    results = vbaparser.analyze_macros()
    for kw_type, keyword, description in results:
        if kw_type in vba_suspicious_type:
            return True
    return False


def is_ole_file(file_message):
    """
        Used to decide if an email.message.Message type attached file is
        ole type file or not
    """

    maintype = file_message.get_content_maintype()
    subtype = file_message.get_content_subtype()
    ole_subtypes = [
        'msword',
        'mspowerpoint',
        'vnd.ms-excel',
        'ms-excel',
    ]
    if maintype == 'application' and subtype in ole_subtypes:
        return True
    return False

def send_msg(smtp_server, username, password, msg):
    """
        @msg : MIMEText type
    """

    s = smtplib.SMTP(smtp_server, 587, timeout=10)
    try:
        s.starttls()
        s.login(username, password)
        s.sendmail(msg['From'], [msg['To']], msg.as_string())
        return True
    except:
        return False
    finally:
        s.quit() # quit no matter exceptions occur

def reply(recipient):

    smtp_server, imap_server, username, password = get_user_info()
    text =  """Don't do nasty thing to me!
"""
    msg = MIMEText(text, 'plain', 'utf-8')
    msg['From'] = username
    msg['To'] = ', '.join([recipient])
    msg['Subject'] = Header("Hi, bad guy!", 'utf-8')
    send_msg(smtp_server, username, password, msg)

def test_scan_all_mails():

    smtp_server, imap_server, username, password = get_user_info()
    imap = IMAPClient(imap_server, username, password)
    imap.scan_all_mails()

def test_monitor_new_mails():

    smtp_server, imap_server, username, password = get_user_info()
    imap = IMAPClient(imap_server, username, password)
    imap.monitor_new_mails()

def test_imap():

    smtp_server, imap_server, username, password = get_user_info()
    m = IMAPClient(imap_server, username, password)
    for i in m.search_mail_uids('ALL'):
        mail = m.peek_mail(i)
        files = mail.get_attached_files()
        for the_file in files:
            print the_file.get_filename(),
            print the_file.is_suspicious()

def test_smtp():

    smtp_server, imap_server, username, password = get_user_info()
    text =  """Don't do nasty thing to me!
"""
    recipients = ["r03922099@ntu.edu.tw"]

    msg = MIMEText(text, 'plain', 'utf-8')
    msg['Subject'] = Header("Hi, bad guy!", 'utf-8')
    msg['From'] = ":)"
    msg['To'] = ', '.join(recipients)

    send_msg(smtp_server, username, password, msg)
    s = smtplib.SMTP(smtp_server, 587, timeout=10)

def test_vba():

    path = './files'
    for the_file in os.listdir(path):
        the_file = path + '/' + the_file
        with open(the_file, 'rb') as f:
            result = is_suspicious(the_file, f.read())
            print the_file + " : is_suspicious() = " + str(result)

def main():

    parser = argparse.ArgumentParser(
        description="Parse attached files in mails in a mailbox " +
                    "and identify suspicious mails.\n" +
                    "two modes\n" +
                    "\t1. scan mode\n" +
                    "\t2. monitor mode\n"
    )
    parser.add_argument('mode', type=str)
    args = parser.parse_args()
    mode = args.mode

    smtp_server, imap_server, username, password = get_user_info()
    imap = IMAPClient(imap_server, username, password)

    if mode == 'scan':
        imap.scan_all_mails()
    elif mode == 'monitor':
        imap.monitor_new_mails()
    elif mode == 'combo':
        imap.scan_all_mails()
        imap.monitor_new_mails()
    else:
        print "mode need to be 'scan' or 'monitor' or 'combo'."

if __name__ == '__main__':

    main()
