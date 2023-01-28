import iocextract
from bs4 import BeautifulSoup
import requests
import sys
import re
import json
import uuid
import datetime
import os
from urllib.parse import urlparse

filtered_tags = [
    'script',
    'meta',
    'link'
]

general_suffixes = [
    '.com',
    '.edu',
    '.gov',
    '.org',
    '.mil',
    '.net',
    '.au', # Australia
    '.in', # India
    '.br', # Brazil
    '.it', # Italy
    '.ca', # Canada
    '.mx', # Mexico
    '.fr', # France
    '.tw', # Tawain
    '.il', # Israel
    '.uk', #United Kingdom
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
            if ioc_key == 'queries' or ioc_key == 'master_query':
                continue
            f.write(50*"#")
            f.write('\n')
            f.write('# {}\n'.format(ioc_key))
            f.write(50*"#")
            f.write('\n\n')
            for ioc in iocs[ioc_key]:
                f.write('{}\n'.format(ioc))
            f.write('\n\n')
            f.write('EQL: {}'.format(iocs['queries'][ioc_key]))
            f.write('\n\n')
        f.write(50*"#")
        f.write('\n')
        f.write('# MASTER EQL QUERY \n')
        f.write(50*"#")
        f.write('\n\n')
        f.write(iocs['master_query'])


def scan_webpage(page_content : str):
    '''
    Filter out any noise from the http request (scripts, links, meta)
    '''
    soup = BeautifulSoup(page_content, 'html.parser')
    soup_str = ''
    for tag in soup.find_all():
        if tag.name not in filtered_tags:
            soup_str += ' {} '.format(tag.text)

    return soup_str

def generate_master_eql_query(iocs : dict):
    master_query = '('
    query_list = []
    for query in iocs['queries'].keys():
        if iocs['queries'][query] != '()':
            query_list.append(iocs['queries'][query])

    for i in range(len(query_list)):
        if i == len(query_list) - 1:
            master_query += '{}'.format(query_list[i])
        else:
            master_query += '{} OR '.format(query_list[i])

    master_query += ')'
    return master_query

def generate_eql_queries(iocs : dict):
    '''
    attempt to generate eql from extracted iocs
    EXCLUDES emails for right now
    '''
    queries = {}
    for ioc_key in iocs.keys():
        query_str = '('
        if ioc_key == 'sha256':
            query_str = 'file.hash.sha256:('
        elif ioc_key == 'sha1':
            query_str = 'file.hash.sha1:('
        elif ioc_key == 'sha512':
            query_str = 'file.hash.sha512:('
        elif ioc_key == 'md5':
            query_str = 'file.hash.md5:('
        elif ioc_key == 'ipv4':
            query_str = 'destination.ip:('
        elif ioc_key == 'urls':
            query_str = 'destination.domain:('
        if ioc_key == 'urls':
            parsed_domains = []
            for url in iocs[ioc_key]:
                if urlparse(url).netloc != '':
                    parsed_domains.append(urlparse(url).netloc)

            for i in range(len(parsed_domains)):
                if i == len(parsed_domains) - 1:
                    query_str += '"{}"'.format(parsed_domains[i])
                else:
                    query_str += '"{}" OR '.format(parsed_domains[i])

        else:
            for i in range(len(iocs[ioc_key])):
                if i == len(iocs[ioc_key]) - 1:
                    query_str += '"{}"'.format(iocs[ioc_key][i])
                else:
                    query_str += '"{}" OR '.format(iocs[ioc_key][i])
        query_str += ')'
        queries[ioc_key] = query_str

    return queries

def ioc_extraction(page_content : str, req_url : str):
    '''
    Loop over iocextraction values, try to find IOCs
    return JSON IOCs payload
    '''
    domain_0 = ''
    domain_1 = ''
    # Attempt to filter out noise of links from the same domain requested
    if 'https' in req_url:
        split_url = req_url.replace('https://', '').split('.')
        domain_0 = split_url[0]
        domain_1 = split_url[1]
    elif 'http' in req_url:
        split_url = req_url.replace('http://', '').split('.')
        domain_0 = split_url[0]
        domain_1 = split_url[1]


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
        # re.match / search to filter out url noise from request domain
        if re.match(urlparse(req_url).netloc, urlparse(url).netloc):
            print("Found a match, skipping")
            continue
        if re.search(urlparse(req_url).netloc, urlparse(url).netloc):
            print("Found a matching search, skipping")
            continue
        if re.search(domain_0, url):
            continue
        if re.search(domain_1, url):
            continue
        # cleanup broken links
        if '[.]' in url:
            url = re.sub('\[.\]', '.', url)
        if 'hxxp' in url:
            url = re.sub('hxxp', 'http', url)
        if url not in ioc_payload['urls']:
            #print(url)
            #print(urlparse(url).netloc)
            ioc_payload['urls'].append(url)

    for ipv4 in iocextract.extract_ipv4s(page_content):
        # cleanup broken IPs
        if '[.]' in ipv4:
            ipv4 = re.sub('\[.\]', '.', ipv4)
        if 'http' in ipv4:
            continue
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
        # cleanup broken emails
        if '(at)' in email:
            email = re.sub('\(at\)', '@', email)
        if '[.]' in email:
            email = re.sub('\[.\]', '.', email)
        if 'at ' in email:
            email = re.sub('at ', '', email)
        if 'mailing-lists-and-feeds  ' in email:
            email = re.sub('mailing-lists-and-feeds  ', '', email)
        if 'hc3  ' in email:
            email = re.sub('hc3  ', '', email)
        if 'via ' in email:
            email = re.sub('via ', '', email)
        if 'field  ' in email:
            email = re.sub('field  ', '', email)
        if 'email ' in email:
            email = re.sub('email ', '', email)
        if 'server hosted' in email:
            continue
        if email not in ioc_payload['email']:
            #print(email)
            ioc_payload['email'].append(email)

    #print(json.dumps(ioc_payload, indent=3))
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
        iocs['queries'] = generate_eql_queries(iocs)
        iocs['master_query'] = generate_master_eql_query(iocs)
        print(json.dumps(iocs, indent=3))
        dump_file(iocs, url)
    else:
        print('error processing request: {}'.format(url))


if __name__ == '__main__':
    for i in range(len(sys.argv)):
        if i == 0:
            continue
        fetch_url(sys.argv[i])