import imapclient

from backports import ssl

from formats import Email, FileMessage

class WrappedIMAP(object):

    MODE_NO_SSL = 0
    MODE_SSL = 1
    MODE_STARTTLS = 2

    def __init__(self, imap_server, username, password, ssl_mode):

        self._mailbox = 'INBOX'
        context = imapclient.tls.create_default_context()
        context.check_hostname = False
        # don't verify the certificate if the certificate is broken
        context.verify_mode = ssl.CERT_NONE
        if ssl_mode == self.MODE_NO_SSL:
            self._imap = imapclient.IMAPClient(
                imap_server, use_uid=True, port=143
            )
        elif ssl_mode == self.MODE_SSL:
            self._imap = imapclient.IMAPClient(
                imap_server, use_uid=True, ssl=True, port=993, ssl_context=context
            )
        elif ssl_mode == self.MODE_STARTTLS:
            # This uses the method named starttls()
            # it use normal port without ssl, and then switch to the tls mode.
            self._imap = imapclient.IMAPClient(imap_server, use_uid=True, port=143)
            self._imap.starttls(ssl_context=context)
        else:
            raise ValueError("WrappedIMAP only supports normal, ssl, starttls")
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
