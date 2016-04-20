import hashlib
import json
import requests
import os
import sys

from formats import FileMessage

class VtAPIError(Exception):

    pass


class VtAPINoReport(Exception):

    pass


def post_file(file_message, api_key):
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
        raise VtAPIError(message)
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

def vt_hash(file_message):
    """
    virustotal api uses the sha256sum of a file as resource_id to
    get scan reports.
    """

    file_hash = hashlib.sha256(
        file_message.get_file_content()
    ).hexdigest()
    return file_hash

def vt_get_scan_report(file_message, api_key):
    """
    Calls virustotal file report api to get the result of a scanned file.
    input:
        file        :   FileMessage type
        api_key     :   str type
    output:
        detected    :   bool type
        message     :   str type
    """

    resource_hash = vt_hash(file_message)
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
    if r.status_code != 200:
        message = "HTTP request failed : "
        message += "\tstatus_code : %d\n" % r.status_code
        message += "\tmessage : %s\n" % r.text
        raise VtAPIError(message)
    ro = json.loads(r.text)
    if ro['response_code'] == 0:
        message = "No report about this file found\n"
        raise VtAPINoReport(message)
    # here we assume that ro['response_code'] == 1,
    # if not, the following code may fail.
    detected = False
    message = "Detection rate : %d/%d\n" % (ro['positives'], ro['total'])
    for sw_name, report in ro['scans'].iteritems():
        if report['detected']:
            message += ("\t%s : %s\n" % (sw_name, report['result']))
        detected |= report['detected']
    return detected, message
