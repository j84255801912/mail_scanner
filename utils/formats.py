#!/usr/bin/env python2.7
# -*- coding : utf-8 -*-

import email
import zipfile

import StringIO

from email.header import Header, decode_header


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
