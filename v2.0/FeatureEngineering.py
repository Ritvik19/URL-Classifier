
# coding: utf-8

import ipaddress as ip
import pickle
import requests, bs4
from datetime import datetime
import re

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

digitCount = lambda x : len(re.findall(r"[\d]", x))

to_datetime = lambda x : datetime(int(x.getText()[:4]), int(x.getText()[5:7]), int(x.getText()[8:]))

def domainRegistrationLength(x):
    try:
        res = requests.get('https://www.whois.com/whois/'+x)
        if res.status_code == requests.codes.ok:
            websitesoup = bs4.BeautifulSoup(res.text)
            elems = websitesoup.select('.df-value')
            regOn, expOn = elems[2:4]
            regOn = to_datetime(regOn)
            expOn = to_datetime(expOn)
            duration = (expOn - regOn).total_seconds()//31556926
            return int(duration)
        else:
            return -1
    except:
        return -1

def alexaGlobalRank(x):
    try:
        res = requests.get('https://www.alexa.com/siteinfo/'+x)
        if res.status_code == requests.codes.ok:
            websitesoup = bs4.BeautifulSoup(res.text)
            elems = websitesoup.select('strong')
            elem = elems[0]
            if elem.getText() == "We don't have enough data to rank this website.":
                return -1
            else:
                elem = elems[6]
                return int(elem.getText().strip())**(-1)
        else:
            return -1
    except:
        return -1

def bounceRate(x):
    try:
        res = requests.get('https://www.alexa.com/siteinfo/'+x)
        if res.status_code == requests.codes.ok:
            websitesoup = bs4.BeautifulSoup(res.text)
            elems = websitesoup.select('strong')
            elem = elems[0]
            if elem.getText() == "We don't have enough data to rank this website.":
                return -1
            else:
                elem = elems[49]
                return float(elem.getText().strip()[:-1])
        else:
            return -1
    except:
        return -1

def dailyPageViewsPerVisitor(x):
    try:
        res = requests.get('https://www.alexa.com/siteinfo/'+x)
        if res.status_code == requests.codes.ok:
            websitesoup = bs4.BeautifulSoup(res.text)
            elems = websitesoup.select('strong')
            elem = elems[0]
            if elem.getText() == "We don't have enough data to rank this website.":
                return -1
            else:
                elem = elems[50]
                return float(elem.getText().strip())
        else:
            return -1
    except:
        return -1

def dailyTimeOnSite(x):
    try:
        res = requests.get('https://www.alexa.com/siteinfo/'+x)
        if res.status_code == requests.codes.ok:
            websitesoup = bs4.BeautifulSoup(res.text)
            elems = websitesoup.select('strong')
            elem = elems[0]
            if elem.getText() == "We don't have enough data to rank this website.":
                return -1
            else:
                elem = elems[51]
                t = elem.getText().strip()
                h = int(t[:-3])
                m = int(t[-2:])
                return ((h*60) + m)
        else:
            return -1
    except:
        return -1

def searchVisits(x):
    try:
        res = requests.get('https://www.alexa.com/siteinfo/'+x)
        if res.status_code == requests.codes.ok:
            websitesoup = bs4.BeautifulSoup(res.text)
            elems = websitesoup.select('strong')
            elem = elems[0]
            if elem.getText() == "We don't have enough data to rank this website.":
                return -1
            else:
                elem = elems[56]
                return float(elem.getText().strip()[:-1])
        else:
            return -1
    except:
        return -1

def totalSitesLinkingIn(x):
    try:
        res = requests.get('https://www.alexa.com/siteinfo/'+x)
        if res.status_code == requests.codes.ok:
            websitesoup = bs4.BeautifulSoup(res.text)
            elems = websitesoup.select('strong')
            elem = elems[0]
            if elem.getText() == "We don't have enough data to rank this website.":
                return -1
            else:
                elem = elems[64]
                return float(elem.getText().strip().replace(',', ''))
        else:
            return -1
    except:
        return -1

def generateFeatures(x):
    features = []
    features.append(length(x))
    features.append(isIp(x))
    features.append(countAt(x))
    features.append(countDoubleSlash(x))
    features.append(countHyphen(x))
    features.append(countDots(x))
    features.append(countDelimeters(x))
    features.append(countSubDirectory(x))
    features.append(countQueries(x))
    features.append(digitCount(x))
    features.append(domainRegistrationLength(x))
    features.append(alexaGlobalRank(x))
    features.append(bounceRate(x))
    features.append(dailyPageViewsPerVisitor(x))
    features.append(dailyTimeOnSite(x))
    features.append(searchVisits(x))
    features.append(totalSitesLinkingIn(x))    
    return features