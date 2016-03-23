#!/usr/bin/env python2.7
# -*- coding : utf-8 -*-

import argparse
import email
import imapclient
import os
import smtplib
import sys
import time

import ConfigParser
import StringIO

from backports import ssl
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
            config.get('root', 'password'),
            config.get('root', 'email')
    )

def get_user_info():

    temp = load_config_file('config')
    return temp

class WrappedIMAP(object):

    def __init__(self, imap_server, username, password, ssl_mode='starttls'):

        self._mailbox = 'INBOX'
        context = imapclient.tls.create_default_context()
        context.check_hostname = False
        # don't verify the certificate if the certificate is broken
        context.verify_mode = ssl.CERT_NONE
        if ssl_mode == 'starttls':
            # This uses the method named starttls()
            # it use normal port without ssl, and then switch to the tls mode.
            self._imap = imapclient.IMAPClient(imap_server, use_uid=True, port=143)
            self._imap.starttls(ssl_context=context)
        elif ssl_mode == 'ssl':
            self._imap = imapclient.IMAPClient(
                imap_server, use_uid=True, ssl=True, port=993, ssl_context=context
            )
        else:
            raise ValueError("WrappedIMAP only supports ssl or starttls")
        # TODO: handle the case when response is 'NO'
        self._imap.login(username, password)
        self._imap.select_folder(self._mailbox) # by default select the mailbox 'INBOX'

    def list_mail_box(self):

        self._imap.list_folders()

    def _refresh_mailbox(self):
        """
            use close() and select() to force mailbox refresh.
        """

        # TODO: this is nasty, should find another way to refresh mailbox
        self._imap.close_folder()
        self._imap.select_folder(self._mailbox)

    def search_mail_uids(self, critirium):

        self._refresh_mailbox()
        result = self._imap.search(critirium)
        return result

    def peek_mail(self, uid):

        # peek doesnt' add the flag \\SEEN
        result = self._imap.fetch([uid], ['BODY.PEEK[]'])
        raw_mail = result[uid]['BODY[]']
        mail = Email(uid, raw_mail)
        return mail

    def peek_mails(self, uids):

        # peek doesnt' add the flag \\SEEN
        result = self._imap.fetch(uids, ['BODY.PEEK[]'])
        mails = [Email(message_id,
                       data['BODY[]']
                )  for message_id, data in result.iteritems()
        ]
        return mails

    def fetch_mail(self, uid):

        result = self._imap.fetch([uid], ['BODY.PEEK[]'])
        raw_mail = result[uid]['BODY[]']
        mail = Email(uid, raw_mail)
        return mail

    '''
    def save_mail_attachments(self, mail, now_time):

        now_time = time.strftime("%Y%m%d_%H%M%S_UTC", now_time)
        mail_path = "./mails/" + now_time
        if not os.path.exists(mail_path):
            os.makedirs(mail_path)

        with open(mail_path + '/mail.txt', 'w') as f:
            f.write(mail.get_raw_mail() + '\n')

        files = mail.get_attached_files()
        for the_file in files:
            with open(mail_path + '/' + the_file.get_filename(), 'w') as f:
                f.write(the_file.get_file_content())
    '''

    def check_mail(self, mail):
        """
            return : a list of suspicious files' name.
        """

        files = mail.get_attached_files()
        suspicious_files = []
        for the_file in files:
            if the_file.is_ole_file() and the_file.is_suspicious():
                suspicious_files.append(the_file.get_filename())

        return suspicious_files

    def scan_all_mails(self):

        print "\nScanning mailbox \"%s\" ...\n" % self._mailbox
        contains_suspicious_mail = False
        mail_uids = self.search_mail_uids('ALL')
        mails = self.peek_mails(mail_uids)
        for mail in mails:
            suspicious_files = self.check_mail(mail)
            if len(suspicious_files) != 0:
                message = "[Suspicious Mail Found] "
                message += "uid=%d; " % mail.get_uid()
                message += "subject=\"%s\"; " % mail.get_subject()
                message += "suspicious_files=\"%s\"" % ', '.join(suspicious_files)
                print message
                contains_suspicious_mail = True
        print "\nDONE\n"
        if not contains_suspicious_mail:
            print "\nCongrats! There is no suspicious mail in your mailbox!\n"

    def monitor_new_mails(self, timeout=2147483647):
        """
            Wait for new mails arrival, and check them.
            Default timeout is 2147483647 seconds.
        """

        last_mail_uids = self.search_mail_uids('ALL')
        last_largest_mail_uid = 0 if len(last_mail_uids) == 0 else last_mail_uids[-1]
        start_time = time.time()
        print "\nWaiting for new mails ...\n"
        while time.time() - start_time < timeout:
            # fetch new mails with bigger uid than the last_biggest one
            new_mail_uids = self.search_mail_uids(
                ['UID', '%d:*' % (last_largest_mail_uid + 1)]
            )
            # if there is no new mail, {last_largest_mail_uid} will be included
            # in new_mail_uids, due to the fact that %d:* means the range from
            # {%d+1} to {last_llargest_mail_uid}.
            try:
                new_mail_uids.remove(last_largest_mail_uid)
            except ValueError:
                pass
            new_mails = self.peek_mails(new_mail_uids)
            for mail in new_mails:
                now_time = time.gmtime()
                # self.save_mail_attachments(mail, now_time)
                suspicious_files = self.check_mail(mail)
                result = len(suspicious_files) != 0

                message = time.strftime("%Y%m%d %H:%M:%S UTC;", now_time)
                message += "[SUSPICIOUS MAIL]" if result else "[SAFE MAIL]"
                message += "uid=%d; " % mail.get_uid()
                message += "subject : " + "\"%s\"; " % mail.get_subject()
                message += "from : \"%s\"; " % mail.get_sender()[1]
                if result:
                    message += "; suspicious_files : " + ', '.join(suspicious_files)
                subject = "[SUSPICIOUS MAIL]" if result else "[SAFE MAIL]"
                subject += " : " + mail.get_subject()
                reply(mail.get_sender()[1], subject, message)
                with open('./log.txt', 'a') as f:
                    f.write(message + '\n')
            if len(new_mail_uids) != 0:
                last_largest_mail_uid = new_mail_uids[-1]
            time.sleep(3)

    def __del__(self):

        self._imap.close_folder() # close the selected mailbox
        self._imap.logout()


class Email(object):

    def __init__(self, uid, rfc822_mail_string):

        self._uid = uid
        self._rfc822 = rfc822_mail_string
        self._message = email.message_from_string(rfc822_mail_string)

    def get_raw_mail(self):

        return self._rfc822

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
            # TODO : deal with other types!
            if part.get_content_maintype() == 'application':
                files.append(FileMessage(part, self))
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

    def is_ole_file(self):
        """
            Used to decide if an email.message.Message type attached file is
            ole type file or not
        """
        file_message = self._file_message
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

def send_msg(smtp_server, username, password, msg, starttls=False):
    """
        @msg : MIMEText type
    """

    s = smtplib.SMTP(smtp_server, 587 if starttls else 25, timeout=10)
    try:
        if starttls:
            s.starttls()
            s.login(username, password)
        s.sendmail(msg['From'], [msg['To']], msg.as_string())
        return True
    except Exception, e:
        print e
        return False
    finally:
        s.quit() # quit no matter exceptions occur

def reply(recipient, subject, text):

    smtp_server, imap_server, username, password, email = get_user_info()
    msg = MIMEText(text, 'plain', 'utf-8')
    msg['From'] = email
    msg['To'] = ', '.join([recipient])
    msg['Subject'] = Header(subject, 'utf-8')
    send_msg(smtp_server, username, password, msg)

def test_scan_all_mails():

    smtp_server, imap_server, username, password, email = get_user_info()
    imap = WrappedIMAP(imap_server, username, password)
    imap.scan_all_mails()

def test_monitor_new_mails():

    smtp_server, imap_server, username, password, email = get_user_info()
    imap = WrappedIMAP(imap_server, username, password)
    imap.monitor_new_mails()

def test_imap():

    smtp_server, imap_server, username, password, email = get_user_info()
    m = WrappedIMap(imap_server, username, password)
    for i in m.search_mail_uids('ALL'):
        mail = m.peek_mail(i)
        files = mail.get_attached_files()
        for the_file in files:
            print the_file.get_filename(),
            print the_file.is_suspicious()

def test_smtp():

    smtp_server, imap_server, username, password, email = get_user_info()
    text =  """Don't do nasty thing to me!
"""
    recipients = ["Mai-Hsuan.Chia@mediatek.com"]

    msg = MIMEText(text, 'plain', 'utf-8')
    msg['Subject'] = Header("Hi, bad guy!", 'utf-8')
    msg['From'] = "Jian-Min.Liu@mediatek.com"
    msg['To'] = ', '.join(recipients)

    send_msg(smtp_server, username, password, msg)

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

    smtp_server, imap_server, username, password, email = get_user_info()
    imap = WrappedIMAP(imap_server, username, password)

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
    #test_smtp()
