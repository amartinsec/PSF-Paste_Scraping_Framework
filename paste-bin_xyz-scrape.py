'''
will need to use typical scraping
will test using secret-agent

every paste just increments key
ex:
    https://paste-bin.xyz/988683 - listed
    https://paste-bin.xyz/988684 - unlisted
    https://paste-bin.xyz/988685 - listed

Even unlisted gets incremented by one. Only difference is that it's not listed in recent pastes

Indexes the following:
    - key/URL
    - keyword match
    - yara match
    - paste content
    - extracted urls
    - extracted emails
    - extracted IPs
    - suspected SSNs
    - paste source
    - paste title
    - paste syntax
    - paste user
    - paste date/time

will only index first 250 lines of paste content and add indacator that it's been truncated

TO IMPLEMENT:
    fix cases where the paste has expired
    FIX GETTING LAST INDEXED KEY FROM ELASTICSEARCH
    get most recent index and sleep if reached

'''

import requests
import json
from pprint import pprint
from tqdm import tqdm
from colorama import Fore, Back
from time import sleep, strptime
import re
from datetime import datetime
from elasticsearch import Elasticsearch
from datetime import datetime
from bs4 import BeautifulSoup as bs
from welcome import *

import yara

welcome_art()

###========================YARA========================###
rules = yara.compile(filepath='yara/index.yar')


###========================ELASTIC========================###
es = Elasticsearch("http://104.248.115.167:9200")
# print (es.info().body)
mappings = {
    "properties": {
        "key": {"type": "text", "analyzer": "standard"},
        "url": {"type": "text", "analyzer": "standard"},
        "content": {"type": "text", "analyzer": "standard"},
        "extracted_urls": {"type": "text", "analyzer": "standard"},
        "extracted_ips": {"type": "text", "analyzer": "standard"},
        "extracted_emails": {"type": "text", "analyzer": "standard"},
        "extracted_common_ssn": {"type": "text", "analyzer": "standard"},
        "hit_type": {"type": "text", "analyzer": "standard"},
        "keyword_match": {"type": "text", "analyzer": "standard"},
        "yara_match_rules": {"type": "text", "analyzer": "standard"},
        "source": {"type": "text", "analyzer": "standard"},
        "paste_title": {"type": "text", "analyzer": "standard"},
        "paste_syntax": {"type": "text", "analyzer": "standard"},
        "paste_user": {"type": "text", "analyzer": "standard"},
        "paste_date_time": {"type": "date", "format": "basic_date_time_no_millis"},

    }
}

# Make new elastic index if not exists
try:
    es.indices.create(index="paste-bin_xyz", mappings=mappings)
except:
    print("Index already exists...")
    pass

# grab keywords from search_terms.txt file and add them to keywords list
keywords = []
try:
    keywords = open('search_terms.txt', 'r').read().split('\n')
except:
    print(Fore.RED + "[-] " + Fore.RESET +"No search_terms.txt file found")


# grab company names from company_names.txt file. 1 per line
try:
    company_names = open('company_names.txt', 'r').read().split('\n')
    keywords = keywords + company_names
except:
    print(Fore.RED + "[-] " + Fore.RESET +"No company_names.txt file found")

while("" in keywords):
    keywords.remove('')

###========================GLOBALS========================###
# List of syntaxes to ignore
ignore_syntax = ['html', 'css', 'swift', 'lua',]


###========================FUNCTIONS========================###
def get_last_index():
    highest=0
    es.indices.refresh(index="paste-bin_xyz")
    last_index = es.search(index="paste-bin_xyz", _source="key",size=10000, query={
    "match_all": {}})

    for hit in last_index['hits']['hits']:
        last_index = hit['_source']['key']
        if int(last_index) > highest:
            highest = int(last_index)

    return highest


def get_paste_content(key):
    # Sleep to avoid rate limiting
    sleep(.25)
    raw_url = "https://paste-bin.xyz/raw/" + key
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'}
    raw_response = requests.get(raw_url, headers=headers)
    if raw_response.status_code == 200 and "Password protected paste" not in raw_response.text:
        return(raw_response.text)
    else:
        return False


def get_paste_meta(key):
    url = "https://paste-bin.xyz/" + key
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'}
    raw_response = requests.get(url, headers=headers)
    soup = bs(raw_response.text, "html.parser")

    #Title of the paste
    paste_title = soup.title.text.replace("- shared code", "")

    #Get paste syntax
    el = soup.find("div", {"id": "paste"}).next
    paste_syntax = el['class']

    #Get paste date-time + user pasting
    paste_user_datetime = soup.find("small", {"class": "title is-6 has-text-weight-normal has-text-grey"}).text
    user = paste_user_datetime.split(" on ")[0].strip("\n")
    user = user.replace("By ", "")
    try:
        paste_datetime  = paste_user_datetime.split(" on ")[1]
        day = re.sub('\D', '', paste_datetime.split(" ")[0])
        month = paste_datetime.split(" ")[1]
        year = paste_datetime.split(" ")[2]
        time = paste_datetime.split(" ")[3] + " " + paste_datetime.split(" ")[4]
        in_time = datetime.strptime(time, "%I:%M:%S %p")
        twenty_four_hour_time = datetime.strftime(in_time, "%H:%M:%S")
        date_time = year + str(strptime(month[:3],'%b').tm_mon)  + day + "T" + twenty_four_hour_time.replace(":", "")
    except Exception as e:
        print(e)
        date_time = ""

    return paste_title, paste_syntax, date_time, user

def send_to_elastic(key, content, hit_type, keyword_match, yara_matches, paste_title, paste_syntax, paste_date_time, paste_user):

    for x in ignore_syntax:
        if x in (paste_syntax) or (x in paste_title):
            print(Fore.RED + "[-] " + Fore.RESET + "Ignoring paste-bin.xyz\\"+str(key) + " " + "due to syntax: " + x)
            return


    print(Fore.GREEN + "[!] " + Fore.RESET + "Sending to cluster..: paste-bin.xyz\\"+str(key) + " due to " + hit_type + "match of " + keyword_match.replace(",", "") + " " + str(yara_matches))

    line_count = content.count("\n")
    if line_count > 250:
        content = content.split("\n")[:250]
        content = "\n".join(content)
        content = content + "\n===============Paste content truncated to only first 250 lines==============="
        content = content + "\n\n[!] Content truncated due to 250+ lines"

    doc = {
        "key": key,
        "url": "https://paste-bin.xyz/" + str(key),
        "content": content,
        "extracted_urls": re.findall("(?P<url>https?://[^\s'\"]+)", content),
        "extracted_ips": re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', content),
        "extracted_emails": re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content),
        "extracted_common_ssn": re.findall(r'^(?!0{3})(?!6{3})[0-8]\d{2}-(?!0{2})\d{2}-(?!0{4})\d{4}$', content),
        "hit_type": hit_type,
        "keyword_match": keyword_match,
        "yara_match_rules": yara_matches,
        "source": "Paste-bin.xyz Scrape",
        "paste_title": paste_title,
        "paste_syntax": paste_syntax,
        "paste_date-time": paste_date_time,
        "paste_user": paste_user

    }
    es.index(index="paste-bin_xyz", document=doc)

###========================LUHNS=CHECKSUM========================###
def luhn_checksum(card_number):
    def digits_of(n):
        return [int(d) for d in str(n)]
    digits = digits_of(card_number)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = 0
    checksum += sum(odd_digits)
    for d in even_digits:
        checksum += sum(digits_of(d*2))
    return checksum % 10


def search_paste_content(key):
    #Get last int in text file
    try:
       key = key
    except:
        print("Issue with the key file...")
        exit()

    paste_data = get_paste_content(str(key))
    if not paste_data:
        #print(Fore.RED + "[-] " + Fore.RESET + "No paste found or paste is password protected for key: " + str(key))
        return
    try:
        paste_meta=get_paste_meta(str(key))
        paste_title = paste_meta[0]
        paste_syntax = paste_meta[1]
        paste_date_time = paste_meta[2]
        paste_user = paste_meta[3]
    except Exception as e:
        print(Fore.RED + "[-] " + Fore.RESET + "Error getting paste meta: " + str(e))
    # Prints the content of the most recent pastes
    hits = 0
    # Check searched_keys buffer size
    keyword_match = ""
    hit_type = ""
    yara_match_type = ""

    #Check for YARA matches on ALL pastes
    yara_matches = rules.match(data=paste_data)

    if yara_matches:
        hit_type += "YARA, "
        yara_match_type = ''.join(str(e) for e in yara_matches)

    urls = re.findall(r'(https?://\S+)', paste_data)
    ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', paste_data)
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', paste_data)
    ssn = re.findall(r'^(?!0{3})(?!6{3})[0-8]\d{2}-(?!0{2})\d{2}-(?!0{4})\d{4}$', paste_data)

    for word in keywords:
            ###========================KEYWORD=REGEX========================###
        if word in paste_data.lower():
            if word not in keyword_match:   keyword_match += (word + ", ")
            # print(keyword_match)
            hits += 1
            if "KEYWORD" not in hit_type:
                hit_type += "KEYWORD, "

                ###========================CC=REGEX========================###
                #Pull suspected CC numbers out of paste
        cc_match = re.findall(r'(?:\d{4}[ \-]?){3}\d{4}', paste_data)
                #Luhns algorithm to validate

    for cc in cc_match:
        if luhn_checksum(cc) == 0 and str(cc)[0] != '0':
            keyword_match += (str(cc) + ", ")
            print("cc match: "+ str(cc))
            hit_type += "CC"
            hits += 1
            if "CC" not in hit_type:
                hit_type += "CC, "

                '''REMOVED DUE TO COVERAGE THROUGH YARA RULE SET
                ###========================BTC=REGEX========================###
                btc_address_match = re.findall(r'/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/g', paste_data)
                if btc_address_match:
                    keyword_match += (str(btc_address_match) + " ")
                    print("btc match: "+ str(btc_address_match))
                    hit_type += "BITCOIN_ADDRESS"
                    hits += 1
                    if "BITCOIN_ADDRESS" not in hit_type:
                        hit_type += "BITCOIN_ADDRESS "
                '''
                ###========================BASE64=REGEX========================###
    base64 = re.findall(r'^@(?=(.{4})*$)[A-Za-z0-9+/]*={0,2}$', paste_data)
    if base64:
        keyword_match += (str(base64) + ", ")
        print("base64 match: " + str(base64))
        hit_type += "BASE64"
        hits += 1
        if "BASE64" not in hit_type:
            hit_type += "BASE64, "


    if hit_type != "":
        send_to_elastic(key, paste_data, hit_type, keyword_match, yara_match_type, paste_title, paste_syntax, paste_date_time, paste_user)
    else:
        pass

def get_newest_paste_index():
    url = "https://paste-bin.xyz/"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'}
    raw_response = requests.get(url, headers=headers)
    soup = bs(raw_response.text, "html.parser")
    return int((soup.find("header", {"class": "bd-category-header my-1"}).find("a")['href'].split("xyz/")[1]))
    print("Last public paste-bin.xyz index: " + str(most_recent_paste_index))


# Main loop
def scrape():
    print("\n" + Fore.GREEN + "[!] " + Fore.RESET +"Starting scrape of paste-bin.xyz")
    print(Fore.GREEN + "[!] " + Fore.RESET + str(len(keywords)) + " keywords included in search")
    starting_index = get_last_index()
    key = starting_index
    print(Fore.GREEN + "[!] " + Fore.RESET +"Last highest index in Elastic cluster: " + str(starting_index))
    most_recent_paste_index = get_newest_paste_index()
    print(Fore.GREEN + "[!] " + Fore.RESET +"Last public paste-bin.xyz index: " + str(most_recent_paste_index))


    while True:
        try:
            if key >= most_recent_paste_index:
                print("Reached most recent paste, sleeping for a day...")
                sleep(86400)
                most_recent_paste_index = get_newest_paste_index()
            else:
                key+=1
                search_paste_content(key)
        except Exception as e:
            print("Error in main loop: ", e)


if __name__ == "__main__":
    scrape()
