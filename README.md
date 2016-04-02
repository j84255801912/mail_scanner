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
smtp_server=smtp.gmail.com
imap_server=imap.gmail.com
email_address=abcdefg@gmail.com
username=abcdefg
password=12345678
```

## Usage
**scan mode** : scanning all mails in the mailbox 'INBOX'
```bsh
$ ./scan_mail.py scan

[Suspicious Mail Found] uid=36; subject="新的"; suspicious_files="SCAN_Invoice_austin.sun.doc"
```
**monitor mode** : monitor mailbox 'INBOX' and scan all new-coming mails.
```bsh
$ ./scan_mail.py monitor

Waiting for new mails ...


[New mail] subject : "dasa"; from : "r03922099@ntu.edu.tw"; result : SAFE
```
**combo mode** : execute scan mode first and then monitor mode.
```bsh
$ ./scan_mail.py combo
```

## TODO
* add more checks in class IMAPClient and other functions to prevent from crash
* refine README.md
* decompose scan_mail.py to multiple files
* refactoring
* remove redundant code
