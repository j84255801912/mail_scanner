#!/usr/bin/env python2.7
# -*- coding : utf-8 -*-

import argparse

from utils.formats import Email, FileMessage
from utils.wrapped_imap import WrappedIMAP
from utils.mail_scanner import MailScanner

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

    ms = MailScanner('./config')

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
