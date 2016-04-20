#!/usr/bin/env python2.7
# -*- coding : utf-8 -*-

import os
import smtplib
import time
import zipfile

import ConfigParser
import StringIO

from email.header import Header, decode_header
from email.mime.text import MIMEText
from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML

from wrapped_imap import WrappedIMAP
from formats import FileMessage
from vt_api import VtAPIError, VtAPINoReport, vt_get_scan_report

class MailScannerError(Exception):

    pass

class MailScanner(object):
    """
    A mail scanner has ability to get attachments in a mailbox, and check
    if they are virus or not.
    """

    def __init__(self, config_file='./config', ssl_mode=WrappedIMAP.MODE_SSL):

        self.load_config_file(config_file)
        self._imap = WrappedIMAP(
            self._imap_config['imap_server'],
            self._imap_config['username'],
            self._imap_config['password'],
            ssl_mode
        )

    def check_config_format(self, config, columns):

        if set(config.keys()) >= set(columns):
            return True
        return False

    def load_config_file(self, config_file):

        config = ConfigParser.RawConfigParser(allow_no_value=True)
        config.read(config_file)
        imap_columns = [
            "imap_server", "username", "password"
        ]
        smtp_columns = [
            "smtp_server", "username", "password", "email_address"
        ]

        # parse imap config
        try:
            self._imap_config = {i[0]:i[1] for i in config.items('imap')}
        except ConfigParser.NoSectionError:
            raise MailScannerError("No imap config in %s" % config_file)
        if not self.check_config_format(self._imap_config, imap_columns):
            raise MailScannerError("imap config is incomplete")

        # parse smtp config
        try:
            self._smtp_config = {i[0]:i[1] for i in config.items('smtp')}
            self._enable_smtp = True
        except ConfigParser.NoSectionError:
            self._smtp_config = None
            self._enable_smtp = False
        if self._enable_smtp and \
           not self.check_config_format(self._smtp_config, smtp_columns):
            self._enable_smtp = False
        # Warning if smtp disabled
        if not self._enable_smtp:
            message = "WARNING : smtp is disabled. "
            message += "MailScanner is unable to send mail."
            print message
        # raise MailScannerError("smtp config is incomplete")

        # parse virustotal api keys
        try:
            self._vt_api_keys = [i[0] for i in config.items('vt_api_keys')]
            self._enable_vt_api = True
        except ConfigParser.NoSectionError:
            self._enable_vt_api = False
        if len(self._vt_api_keys) == 0:
            self._enable_vt_api = False
        # Warning if virustotal api disabled
        if not self._enable_vt_api:
            message = "WARNING : virustotal api is disabled. "
            message += "Some checks may be ignored."
            print message

    def send_msg(self, msg, starttls=False):
        """
            @msg : MIMEText type
        """

        try:
            s = smtplib.SMTP(
                    self._smtp_config['smtp_server'],
                    587 if starttls else 25,
                    timeout=10
            )
        except Exception, e:
            print "Failed to connect to smtp server",
            print e
            return False
        try:
            if starttls:
                s.starttls()
                s.login(
                    self._smtp_config['username'],
                    self._smtp_config['password']
                )
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
        msg['From'] = self._smtp_config['email_address']
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
        vba_suspicious_type = vba_types
        vbaparser = VBA_Parser(filename, file_content)

        if not vbaparser.detect_vba_macros():
            return False
        results = vbaparser.analyze_macros()
        for kw_type, keyword, description in results:
            if kw_type in vba_suspicious_type:
                vbaparser.close()
                return True
        vbaparser.close()
        return False

    def check_vt_api(self, file_message):

        api_key = self._vt_api_keys[0]
        try:
            detected, message = vt_get_scan_report(file_message, api_key)
            return detected, message
        except VtAPINoReport, e:
            ret = "Warning: virustotal API has no report; "
            ret += "filename: {} ; ".format(file_message.get_filename())
            ret += "Reason: {}".format(str(e))
            print ret
        except VtAPIError, e:
            ret = "Warning: virustotal API error; "
            ret += "filename: {} ; ".format(file_message.get_filename())
            ret += "Reason: {}".format(str(e))
            print ret
        return False, ""

    def check_regular_file(self, file_message):

        result = False
        if file_message.is_ole():
            result |= self.check_vba(file_message)
        if self._enable_vt_api:
            detected, message = self.check_vt_api(file_message)
            result |= detected
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
        result = False
        for i in the_zip.infolist():
            # skip directories
            if os.path.basename(i.filename) == '':
                continue
            encrypted = i.flag_bits & 0x01
            if encrypted:
                f = the_zip.open(i.filename, pwd='123')
            else:
                f = the_zip.open(i.filename)
            this_file = FileMessage(i.filename, f.read())
            result |= self.check_file(this_file)
        return result

    def check_file(self, file_message):
        """
            return if this file is suspicious.
        """

        if file_message.is_zip():
            return self.check_zip(file_message)

        pass # TODO : do other extractions like rar, ...

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
                result = (len(suspicious_files) != 0)

                message = time.strftime("%Y%m%d %H:%M:%S UTC ", now_time)
                message += "[SUSPICIOUS MAIL] " if result else "[SAFE MAIL] "
                message += "uid=%d; " % mail.get_uid()
                message += "subject : " + "\"%s\"; " % mail.get_subject()
                message += "from : \"%s\"; " % mail.get_sender()[1]
                if result:
                    message += "; suspicious_files : " + ', '.join(suspicious_files)
                subject = "[SUSPICIOUS MAIL]" if result else "[SAFE MAIL]"
                subject += " : " + mail.get_subject()
                if self._enable_smtp:
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
