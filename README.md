Mail Scanner
-------------------
by j84255801912@gmail.com

## Dependency
```bsh
$ pip install oletools imapclient
```

## Configure files
**[example]**
```bsh
$ vim config
```

config
```config
[imap]
imap_server=imap.gmail.com
username=abcdefg
password=12345678
[smtp]
smtp_server=smtp.gmail.com
email_address=abcdefg@gmail.com
username=abcdefg
password=12345678
[vt_api_keys]
12345678901234567890
09876543210987654321
```

## Usage
**scan mode** : scanning all mails in the mailbox 'INBOX'
```bsh
$ ./main.py scan

[Suspicious Mail Found] uid=36; subject="新的"; suspicious_files="SCAN_Invoice_austin.sun.doc"
```
**monitor mode** : monitor mailbox 'INBOX' and scan all new-coming mails.
```bsh
$ ./main.py monitor

Waiting for new mails ...


[New mail] subject : "dasa"; from : "r03922099@ntu.edu.tw"; result : SAFE
```
You can see the mail log in the file "mail.log".
**combo mode** : execute scan mode first and then monitor mode.
```bsh
$ ./scan_mail.py combo
```

## TODO
* support more kinds of connections with complete functions
* add more checks in class IMAPClient and other functions to prevent from crash
* refine README.md
* refactoring
* remove redundant code
