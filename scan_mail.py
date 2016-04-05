#!/usr/bin/env python2.7
# -*- coding : utf-8 -*-

import argparse
import email
import imapclient
import os
import smtplib
import sys
import time
import zipfile

import ConfigParser
import StringIO

from backports import ssl
from email.header import Header, decode_header
from email.mime.text import MIMEText
from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML


class MailScanner(object):
    """
    A mail scanner has ability to get attachments in a mailbox, and check
    if they are virus or not.
    """

    def __init__(self):

        self._smtp_server, self._imap_server, self._username,\
            self._password, self._email_address = self.get_user_info()
        self._imap = WrappedIMAP(
            self._imap_server, self._username, self._password
        )

    def load_config_file(self, config_file):

        with open(config_file, 'rb') as f:
            file_content = "[root]\n"
            file_content += f.read()
        content_str_fp = StringIO.StringIO(file_content)
        config = ConfigParser.RawConfigParser()
        config.readfp(content_str_fp)
        return (config.get('root', 'smtp_server'),
                config.get('root', 'imap_server'),
                config.get('root', 'username'),
                config.get('root', 'password'),
                config.get('root', 'email_address')
        )

    def get_user_info(self):

        temp = self.load_config_file('./config')
        return temp

    def send_msg(self, msg, starttls=False):
        """
            @msg : MIMEText type
        """

        s = smtplib.SMTP(self._smtp_server, 587 if starttls else 25, timeout=10)
        try:
            if starttls:
                s.starttls()
                s.login(self._username, self._password)
            s.sendmail(msg['From'], [msg['To']], msg.as_string())
            return True
        except Exception, e:
            print "Failed to send mail"
            print e
            return False
        finally:
            s.quit() # quit no matter exceptions occur

    def reply(self, recipient, subject, text):

        msg = MIMEText(text, 'plain', 'utf-8')
        msg['From'] = self._email_address
        msg['To'] = ', '.join([recipient])
        msg['Subject'] = Header(subject, 'utf-8')
        self.send_msg(msg)

    def check_vba(self, file_message):

        filename = file_message.get_filename()
        file_content = file_message.get_file_content()

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

    def check_regular_file(self, file_message):

        result = False
        if file_message.is_ole():
            result |= self.check_vba(file_message)

        pass  # TODO : here can be multiple checks.

        return result

    def check_zip(self, file_message):
        """
            return if this zip is suspicious
        """

        # this supports recursively unzip
        the_zip = zipfile.ZipFile(file_message.get_file_object())
        # infolist automatically show all files and dirs.
        # In this for loop, some f will be dirs instead of regular files.
        # These cases, f.read() == "", and f.get_filename() like "dir/dir/"
        # It makes checks works normally.
        for i in the_zip.infolist():
            encrypted = i.flag_bits & 0x01
            if encrypted:
                f = the_zip.open(i.filename, pwd='123')
            else:
                f = the_zip.open(i.filename)
            this_file = FileMessage(i.filename, f.read())
            if self.check_file(this_file):
                return True
        return False

    def check_file(self, file_message):
        """
            return if this file is suspicious.
        """

        if file_message.is_zip():
            return self.check_zip(file_message)

        pass # TODO : do other extracts like rar, ...

        return self.check_regular_file(file_message)

    def check_mail(self, mail):
        """
            return : a list of suspicious files' name.
        """

        files = mail.get_attached_files()
        suspicious_files = []
        for the_file in files:
            if self.check_file(the_file):
                suspicious_files.append(the_file.get_filename())
        return suspicious_files

    def scan_all_mails(self):

        imap = self._imap
        print "\nScanning mailbox \"%s\" ...\n" % imap.get_current_mailbox()
        contains_suspicious_mail = False
        mail_uids = imap.search_mail_uids('ALL')
        mails = imap.peek_mails(mail_uids)
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

        imap = self._imap
        last_mail_uids = imap.search_mail_uids('ALL')
        last_largest_mail_uid = 0 if len(last_mail_uids) == 0 else last_mail_uids[-1]
        start_time = time.time()
        print "\nWaiting for new mails ...\n"
        while time.time() - start_time < timeout:
            # fetch new mails with bigger uid than the last_biggest one
            new_mail_uids = imap.search_mail_uids(
                ['UID', '%d:*' % (last_largest_mail_uid + 1)]
            )
            # if there is no new mail, {last_largest_mail_uid} will be included
            # in new_mail_uids, due to the fact that %d:* means the range from
            # {%d+1} to {last_llargest_mail_uid}.
            try:
                new_mail_uids.remove(last_largest_mail_uid)
            except ValueError:
                pass
            new_mails = imap.peek_mails(new_mail_uids)
            for mail in new_mails:
                now_time = time.gmtime()
                # self.save_mail_attachments(mail, now_time)
                suspicious_files = self.check_mail(mail)
                result = len(suspicious_files) != 0

                message = time.strftime("%Y%m%d %H:%M:%S UTC ", now_time)
                message += "[SUSPICIOUS MAIL] " if result else "[SAFE MAIL] "
                message += "uid=%d; " % mail.get_uid()
                message += "subject : " + "\"%s\"; " % mail.get_subject()
                message += "from : \"%s\"; " % mail.get_sender()[1]
                if result:
                    message += "; suspicious_files : " + ', '.join(suspicious_files)
                subject = "[SUSPICIOUS MAIL]" if result else "[SAFE MAIL]"
                subject += " : " + mail.get_subject()
                self.reply(mail.get_sender()[1], subject, message)
                with open('./mail.log', 'ab') as f:
                    f.write(message + '\n')
            if len(new_mail_uids) != 0:
                last_largest_mail_uid = new_mail_uids[-1]
            time.sleep(3)
    '''
    def save_mail_attachments(self, mail, now_time):

        now_time = time.strftime("%Y%m%d_%H%M%S_UTC", now_time)
        mail_path = "./mails/" + now_time
        if not os.path.exists(mail_path):
            os.makedirs(mail_path)

        with open(mail_path + '/mail.txt', 'wb') as f:
            f.write(mail.get_raw_mail() + '\n')

        files = mail.get_attached_files()
        for the_file in files:
            with open(mail_path + '/' + the_file.get_filename(), 'wb') as f:
                f.write(the_file.get_file_content())
    '''


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

    def get_current_mailbox(self):

        return self._mailbox

    def list_all_mailbox(self):

        return self._imap.list_folders()

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

        def extract_file_from_message(file_message):
            """
            extract filename and file_content from a
            email.message.Message
            """

            filename, charset = decode_header(file_message.get_filename())[0]
            if charset:
                filename = filename.decode(charset)
            file_content = file_message.get_payload(decode=True)
            return FileMessage(filename, file_content)

        if self._message.get_content_maintype() != 'multipart':
            return []
        files = []
        for part in self._message.walk():
            # If a part is an attachment, it must have 'Content-Disposition'
            # field in the part of its body.
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get('Content-Disposition') == None:
                continue
            files.append(extract_file_from_message(part))
        return files


class FileMessage(object):
    """
        this class is used to handle the email.message.Message type attached
        files.
    """

    def __init__(self, filename, file_content):

        self._filename = filename
        self._file_content = file_content
        self._file_object = StringIO.StringIO(file_content)

    def get_filename(self):

        return self._filename

    def get_file_content(self):

        return self._file_content

    def get_file_object(self):

        return self._file_object

    def is_zip(self):

        return zipfile.is_zipfile(self._file_object)

    def is_rar(self):

        return False

    def is_ole(self):
        """
            Used to decide if an email.message.Message type attached file is
            ole type file or not
        """

        ole_types = (
            '.doc', '.docx'
        )
        if self.get_filename().lower().endswith(ole_types):
            return True
        return False


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
            print check_vba(the_file)

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
            result = check_vba(the_file, f.read())
            print the_file + " : check_vba() = " + str(result)

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

    ms = MailScanner()

    if mode == 'scan':
        ms.scan_all_mails()
    elif mode == 'monitor':
        ms.monitor_new_mails()
    elif mode == 'combo':
        ms.scan_all_mails()
        ms.monitor_new_mails()
    else:
        print "mode need to be 'scan' or 'monitor' or 'combo'."

if __name__ == '__main__':

    main()
    #test_smtp()
