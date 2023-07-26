'''
Pastebin scraping permissions

1x per minute the 100 most recent pastes
store keys then fetch all pastes to process

recent pasts return in standard JSON
https://scrape.pastebin.com/api_scraping.php?limit=<1-250>
Default amount is 50, but max can be 250

can use API
DO NOT GO OVER 100 PER MINUTE OR WILL BE BLOCKED FOR 24 HOURS

TODO/LOGIC:
    - get_recent_pastes() returns a list of dicts
    locally store the keys of the pastes for ~ 200? pastes
    fetch all pastes and compare for regex
    ship off valid pastes to Elastic
    Add UI 
    Add screenshot functionality for links
    Add bulk delete in UI
    Add user auth
    convert epoch date to human readable
    filter out HTML
    add size limit to indexing pastes
    add other site scraping
'''

import requests
import json
from pprint import pprint
from tqdm import tqdm
from colorama import Fore, Back
from time import sleep
import re
from datetime import datetime
from elasticsearch import Elasticsearch
from datetime import datetime

import yara


###========================YARA========================###
rules = yara.compile(filepath='yara/index.yar')


###========================ELASTIC========================###
es = Elasticsearch("http://104.248.115.167:9200")
# print (es.info().body)
mappings = {
    "properties": {
        "key": {"type": "text", "analyzer": "standard"},
        "date": {"type": "date", "analyzer": "date_hour_minute_second"},
        "title": {"type": "text", "analyzer": "standard"},
        "user": {"type": "text", "analyzer": "standard"},
        "syntax": {"type": "text", "analyzer": "standard"},
        "content": {"type": "text", "analyzer": "standard"},
        "extracted_urls": {"type": "text", "analyzer": "standard"},
        "extracted_ips": {"type": "text", "analyzer": "standard"},
        "extracted_emails": {"type": "text", "analyzer": "standard"},
        "extracted_common_passwords": {"type": "text", "analyzer": "standard"},
        "extracted_common_ssn": {"type": "text", "analyzer": "standard"},
        "hit_type": {"type": "text", "analyzer": "standard"},
        "keyword_match": {"type": "text", "analyzer": "standard"},
        "expire": {"type": "date", "format": "date_hour_minute_second"},
        "yara_match_rules": {"type": "text", "analyzer": "standard"},
        "source": {"type": "text", "analyzer": "standard"},

    }
}

# Make new elastic index if not exists
try:
    es.indices.create(index="pastebin_scrape_com", mappings=mappings)
except:
    print("Index already exists")
    pass

# grab keywords from search_terms.txt file and add them to keywords list
keywords = []
try:
    keywords = open('search_terms.txt', 'r').read().split('\n')
except:
    print("No search_terms.txt file found")


# grab company names from company_names.txt file. 1 per line
try:
    company_names = open('company_names.txt', 'r').read().split('\n')
    keywords = keywords + company_names
except:
    print("No company_names.txt file found")

# On linux, '' was being added to the search terms making the search match on everything
# This removes any empty strings from the list
while("" in keywords):
    keywords.remove('')


###========================GLOBALS========================###
# List to track searched keys
# Tracks last 200 keys
searched_keys = []

# List of syntaxes to ignore
ignore_syntax = ['html', 'css', 'js', 'java', 'swift', 'lua']

# List of titles to ignore
ignore_titles = ['lab','algorithm','assignment']

###========================FUNCTIONS========================###
def get_recent_pastes(limit=100):
    # Returns a list of the most recent pastes (default 50)
    url = f'https://scrape.pastebin.com/api_scraping.php?limit={limit}'
    response = requests.get(url)
    val = response.json()
    return val


def get_paste_content(key):
    # Sleep to avoid rate limiting
    sleep(.25)
    scrape_url = "https://scrape.pastebin.com/api_scrape_item.php?i=" + key
    response = requests.get(scrape_url)
    return [response.text, scrape_url]


def send_to_elastic(key, date, title, user, syntax, content, hit_type, keyword_match, expire,yara_matches):
    doc = {
        "key": key,
        "date": date,
        "title": title,
        "user": user,
        "syntax": syntax,
        "content": content,
        "extracted_urls": re.findall("(?P<url>https?://[^\s'\"]+)", content),
        "extracted_ips": re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', content),
        "extracted_emails": re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content),
        "extracted_common_passwords": re.findall(r'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).{8,}$', content),
        "extracted_common_ssn": re.findall(r'^(?!0{3})(?!6{3})[0-8]\d{2}-(?!0{2})\d{2}-(?!0{4})\d{4}$', content),
        "hit_type": hit_type,
        "keyword_match": keyword_match,
        "expire": expire,
        "yara_match_rules": yara_matches,
        "source": "Pastebin.com API"

    }
    es.index(index="pastebin_scrape_com", document=doc)

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



def search_paste_content(json_actual):
    # Prints the content of the most recent pastes
    hits = 0
    # Check searched_keys buffer size
    for paste in json_actual:
        keyword_match = ""
        hit_type = ""
        yara_match_type = ""
        if len(searched_keys) >= 200:
            searched_keys.pop(0)

        if paste['key'] not in searched_keys:
            searched_keys.append(paste['key'])
            paste_data = get_paste_content(paste['key'])[0]

            # Check for YARA matches on ALL pastes
            yara_matches = rules.match(data=paste_data)

            if yara_matches:
                hit_type += "YARA, "
                yara_match_type = ''.join(str(e) for e in yara_matches)

            urls = re.findall(r'(https?://\S+)', paste_data)
            ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', paste_data)
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', paste_data)
            passwords = re.findall(r'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).{8,}$',
                                                     paste_data)
            ssn = re.findall(r'^(?!0{3})(?!6{3})[0-8]\d{2}-(?!0{2})\d{2}-(?!0{4})\d{4}$', paste_data)

            # Ignore junk syntax for keyword search if it's not a yara match, or no other regex criteria is met
            if any([x in paste['syntax'].lower() for x in ignore_syntax]) and (not yara_matches or not urls or not ips or not emails or not passwords or not ssn):
                pass

            if any([x in paste['title'].lower() for x in ignore_titles]):
                pass

            # Start of keyword searching logic
            else:
                for word in keywords:
                    ###========================KEYWORD=REGEX========================###
                    if word in paste_data.lower():
                        keyword_match += (word + ", ")
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

                '''REMOVED DUE TO YARA RULE COVERAGE
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
                    send_to_elastic(paste['key'], datetime.fromtimestamp(int(paste['date'])), paste['title'],
                                    paste['user'], paste['syntax'], paste_data, hit_type, keyword_match,
                                    datetime.fromtimestamp(int(paste['expire'])),yara_match_type)
        else:
            pass


# Main loop
def scrape():
    print("Starting scrape searching for the following keywords and company names:")
    print(keywords)
    print("\nExcluding the following syntax types from keyword search:")
    print(ignore_syntax)

    while True:
        try:
            search_paste_content(get_recent_pastes(100))
        except Exception as e:
            print("Error: ", e)
        sleep(60)


if __name__ == "__main__":
    scrape()
