# Mail Scanner
-------------------
by j84255801912@gmail.com

## Dependency
```bsh
$ pip install oletools
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
username=abcdefg@gmail.com
password=12345678
```

## Usage
**scan mode** : scanning all mails in the mailbox 'INBOX'
```bsh
$ ./scan_mail.py scan

Congrats! There is no suspicious mail in your mailbox!
```
**monitor mode** : monitor mailbox 'INBOX' and scan all new-coming mails.
```bsh
$ ./scan_mail.py monitor
```

## TODO
* check if virus mail detection works or not.
* refine README.txt
* refactoring
* remove redundant code
