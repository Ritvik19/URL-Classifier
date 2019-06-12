import pandas as pd

import ipaddress as ip
import requests, bs4
from datetime import datetime
import re

def drl_cleaner(x):
    try:
        return int(x)
    except:
        return -1
    
def st_br_cleaner(x):
    try:
        return float(x[:-1])
    except:
        return -1
    
def tsli_ar_cleaner(x):
    try:
        return int(x.replace('#', '').replace(',', ''))
    except:
        return -1

def dvpv_cleaner(x):
    try:
        return float(x)
    except:
        return -1
    
def dtos_cleaner(x):
    try:
        if ':' in x:
            a, b = x.split(':')
            return int(a)*60+int(b)
        else:
            return -1
    except:
        return -1
    
length = lambda x : len(x)

def isIp(x):
    try:
        if ip.ip_address(x):
            return 1
    except:
        return 0
    
countAt = lambda x : x.count('@')

countDoubleSlash = lambda x : x.count('//')

countHyphen = lambda x : x.count('-')

countDots = lambda x: x.count('.')

def countDelimeters(x):
    count = 0
    for delim in [';','_','?','=','&']:
        count += x.count(delim)
    return count

countSubDirectory = lambda x : len(re.findall(r"[\s/\s]", x))

def countQueries(x):
    if not x:
        return 0
    else:
        return len(x.split('&'))
    
to_datetime = lambda x : datetime(int(x[:4]), int(x[5:7]), int(x[8:]))

def websiteInfo(website):

    website_details = {'URL': [website]}
    try:
        url = 'https://www.whois.com/whois/'+website
        res = requests.get(url)
        if res.status_code == requests.codes.ok:
            ressoup = bs4.BeautifulSoup(res.text, 'lxml')
            elems = ressoup.select('.df-value')
            try:
                regOn = to_datetime(elems[2].getText())
                expOn = to_datetime(elems[3].getText())
                duration = (expOn - regOn).total_seconds()//31556926
                website_details['Domain Registration Length'] = [int(duration)]
            except Exception as e:
                website_details['Domain Registration Length'] = [-1]
        else:
            website_details['Domain Registration Length'] = [-1]
    except Exception as e:
        website_details['Domain Registration Length'] = [-1]
        
    try:
        url = 'https://www.alexa.com/siteinfo/'+website
        res = requests.get(url)
        if res.status_code == requests.codes.ok:
            ressoup = bs4.BeautifulSoup(res.text, 'lxml')

            elems = ressoup.select('.num.purple')
            try:
                website_details['Search Traffic'] = [st_br_cleaner(elems[0].getText())]
            except Exception as e:
                website_details['Search Traffic'] = [-1]
            try:
                website_details['Bounce Rate'] = [st_br_cleaner(elems[1].getText())]
            except Exception as e:
                website_details['Bounce Rate'] = [-1]

            elems = ressoup.select('.big.data')
            try:
                website_details['Total Sites Linking in'] = [tsli_ar_cleaner(elems[1].getText())]
            except Exception as e:
                website_details['Total Sites Linking in'] = [-1]

            elems = ressoup.select('.rankmini-rank')
            try:
                website_details['Alexa Rank'] = [tsli_ar_cleaner(elems[0].getText().strip())**-1]
            except Exception as e:
                website_details['Alexa Rank'] = [-1]

            elems = ressoup.select('.small.data')
            try:
                website_details['Daily Views per Visitor'] = [dvpv_cleaner(elems[1].getText().strip().split()[0])]
            except Exception as e:
                website_details['Daily Views per Visitor'] = [-1]
            try:
                website_details['Daily Time on Site'] = [dtos_cleaner(elems[2].getText().strip().split()[0])]
            except Exception as e:
                website_details['Daily Time on Site'] = [-1]
        else:
            website_details['Search Traffic'] = [-1]
            website_details['Bounce Rate'] = [-1]
            website_details['Total Sites Linking in'] = [-1]
            website_details['Alexa Rank'] = [-1]
            website_details['Daily Views per Visitor'] = [-1]
            website_details['Daily Time on Site'] = [-1]
    except Exception as e:
        website_details['Search Traffic'] = [-1]
        website_details['Bounce Rate'] = [-1]
        website_details['Total Sites Linking in'] = [-1]
        website_details['Alexa Rank'] = [-1]
        website_details['Daily Views per Visitor'] = [-1]
        website_details['Daily Time on Site'] = [-1]
    
    website_details['Length'] = [length(website)]
    website_details['Is IP'] = [isIp(website)]
    website_details['Count @'] = [countAt(website)]
    website_details['Count Double Slash'] = [countDoubleSlash(website)]
    website_details['Count Hyphen'] = [countHyphen(website)]
    website_details['Count Dots'] = [countDots(website)]
    website_details['Count Delimeters'] = [countDelimeters(website)]
    website_details['Count Subdirectory '] = [countSubDirectory(website)]
    website_details['Count Queries '] = [countQueries(website)]
#     print(website_details)
    website_details = pd.DataFrame(website_details)

    return website_details