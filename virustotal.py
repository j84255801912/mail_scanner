import json
import requests
import os

from scan_mail import FileMessage
from vtkeyfile import api_key

def post_file(file_message):
    """
    Posts files to virustotal.com,
    """

    filename = file_message.get_filename()
    file_content = file_message.get_file_content()
    upload_url = "https://www.virustotal.com/vtapi/v2/file/scan"
    # * The requests module allows multiple file uploads.
    #       http://docs.python-requests.org/en/latest/user/advanced/#advanced
    #   However, virustotal seems accept one file at one time.
    # * files list should contain tuples in the following format
    #   ({form_name}, ({filename, file-object or file_content_string}))
    files = [
        ('file', (filename, file_content)),
    ]
    """
    files = {
        'file' : (filename,
                  open(file_path, 'rb')
        )
    }
    """
    r = requests.post(
        upload_url,
        data={
            'apikey'    :   api_key,
        },
        files=files
    )

    # r.status_code == 403 if without autherization.
    # r.status_code == 204 if exceed public API request rate.
    if r.status_code != 200:
        message = "HTTP request failed : "
        message += "\tstatus_code : %d\n" % r.status_code
        message += "\tmessage : %s\n" % r.text
        raise ValueError(message)
    ro = json.loads(r.text)
    # ro has keys : permalink, sha1, resource, response_code, scan_id,
    #               verbose_msg, sha256, md5
    print ro
    response_code = ro['response_code']
    if response_code == 0:
        # if the item you searched for was not present in VirusTotal's dataset
        pass
    elif response_code == -2:
        pass
    return ro['resource']

def query_result(resource_hash):
    """
    Calls virustotal file report api to get the result of a scanned file.
    """

    retrieve_report_url = "https://www.virustotal.com/vtapi/v2/file/report"
    r = requests.post(
        retrieve_report_url,
        data = {
            'apikey'    :   api_key,
            'resource'  :   resource_hash,
        },
    )
    # r.status_code == 403 if without autherization.
    # r.status_code == 204 if exceed public API request rate.
    print r.status_code
    ro = json.loads(r.text)
    print ro

def main():

    with open('files/README.md', 'rb') as f:
        fm = FileMessage('README.md', f.read())
        post_file(fm)

if __name__ == '__main__':

    main()
