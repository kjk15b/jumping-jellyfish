import iocextract
from bs4 import BeautifulSoup
import requests
import sys
import re
import json
import uuid
import datetime
import os

filtered_tags = [
    'script',
    'meta',
    'link'
]

def dump_file(iocs : dict, url : str):
    '''
    Dump scan results to txt file on disk with UUID and timestamp
    '''
    filename = '{}-{}.txt'.format(str(uuid.uuid4()), str(datetime.date.today()))
    fname = os.path.join(os.getcwd(), 'processed/', filename)
    with open(fname, 'w') as f:
        f.write('Scan: {}'.format(url))
        f.write('\n\n')
        for ioc_key in iocs.keys():
            f.write(50*"#")
            f.write('\n')
            f.write('# {}\n'.format(ioc_key))
            f.write(50*"#")
            f.write('\n\n')
            for ioc in iocs[ioc_key]:
                f.write('{}\n'.format(ioc))
            f.write('\n\n')



def scan_webpage(page_content : str):
    '''
    Filter out any noise from the http request (scripts, links, meta)
    '''
    soup = BeautifulSoup(page_content, 'html.parser')
    soup_str = ''
    for tag in soup.find_all():
        if tag.name not in filtered_tags:
            soup_str += ' {} '.format(tag.text)

    #print(soup_str)
    return soup_str

def ioc_extraction(page_content : str, req_url : str):
    '''
    Loop over iocextraction values, try to find IOCs
    return JSON IOCs payload
    '''
    ioc_payload = {
        'urls'   : [],
        'ipv4'   : [],
        'ipv6'   : [],
        'md5'    : [],
        'sha256' : [],
        'sha512' : [],
        'sha1'   : [],
        'email'  : []
    }
    for url in iocextract.extract_urls(page_content):
        if re.match(req_url, url):
            continue
        if '[.]' in url:
                url = re.sub('\[.\]', '.', url)
        if url not in ioc_payload['urls']:
            #print(url)
            ioc_payload['urls'].append(url)

    for ipv4 in iocextract.extract_ipv4s(page_content):
        if ipv4 not in ioc_payload['ipv4']:
            #print(ipv4)
            ioc_payload['ipv4'].append(ipv4)
    '''
    for ipv6 in iocextract.extract_ipv6s(page_content):
        if ipv6 not in ioc_payload['ipv6']:
            #print(ipv6)
            ioc_payload['ipv6'].append(ipv6)
    '''
    for md5 in iocextract.extract_md5_hashes(page_content):
        if md5 not in ioc_payload['md5']:
            #print(md5)
            ioc_payload['md5'].append(md5)

    for sha1 in iocextract.extract_sha1_hashes(page_content):
        if sha1 not in ioc_payload['sha1']:
            #print(sha1)
            ioc_payload['sha1'].append(sha1)

    for sha256 in iocextract.extract_sha256_hashes(page_content):
        if sha256 not in ioc_payload['sha256']:
            #print(sha256)
            ioc_payload['sha256'].append(sha256)

    for sha512 in iocextract.extract_sha512_hashes(page_content):
        if sha512 not in ioc_payload['sha512']:
            #print(sha512)
            ioc_payload['sha512'].append(sha512)

    for email in iocextract.extract_emails(page_content):
        if '(at)' in email:
            email = re.sub('\(at\)', '@', email)
        if email not in ioc_payload['email']:
            #print(email)
            ioc_payload['email'].append(email)

    print(json.dumps(ioc_payload, indent=3))
    return ioc_payload

def fetch_url(url : str):
    '''
    Collect user input url and
    attempt to return a 200 status code on successful GET
    '''
    req = requests.get(url)
    if req.status_code == 200:
        proc_page = scan_webpage(req.content)
        iocs = ioc_extraction(proc_page, url)
        dump_file(iocs, url)
    else:
        print('error processing request: {}'.format(url))


if __name__ == '__main__':
    for i in range(len(sys.argv)):
        if i == 0:
            continue
        fetch_url(sys.argv[i])