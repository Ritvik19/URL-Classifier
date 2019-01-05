
# coding: utf-8

# # Importing Libraries

# In[1]:


import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns


# In[2]:


import ipaddress as ip
import pickle
import requests, bs4
from datetime import datetime
import re


# In[3]:


pd.options.display.max_columns = 50

get_ipython().magic('matplotlib inline')


# # Importing Data and EDA

# In[4]:


dataset = pd.read_csv('dataset.csv')


# In[5]:


dataset.head()


# In[6]:


len(dataset)


# In[7]:


dataset['Label'].value_counts()


# # Feature Generartion

# ##### 01.  Long URL to Hide the Suspicious Part
# Phishers can use long URL to hide the doubtful part in the address bar. For example: 
# http://federmacedoadv.com.br/3f/aze/ab51e2e319e51502f416dbe46b773a5e/?cmd=_home&amp;dispatch=11004d58f5b74f8dc1e7c2e8dd4105e811004d58f5b74f8dc1e7c2e8dd4105e8@phishing.website.html

# In[8]:


length = lambda x : len(x)


# ##### 02. Using the IP Address
# If an IP address is used as an alternative of the domain name in the URL, such as “http://125.98.3.123/fake.html”, users can be sure that someone is trying to steal their personal information. Sometimes, the IP address is even transformed into hexadecimal code as shown in the following link “http://0x58.0xCC.0xCA.0x62/2/paypal.ca/index.html”. 
# 
# If the domain part has an IP address -> Phishing
# 
# Otherwise -> Legitimate

# In[9]:


def isIp(x):
    try:
        if ip.ip_address(x):
            return 1
    except:
        return 0


# ##### 03. URL’s having “@” Symbol
# Using “@” symbol in the URL leads the browser to ignore everything preceding the “@” symbol and the real address often follows the “@” symbol. 

# In[10]:


countAt = lambda x : x.count('@')


# ##### 04. Redirecting using “//”
# The existence of “//” within the URL path means that the user will be redirected to another website. An example of such URL’s is: “http://www.legitimate.com//http://www.phishing.com”. We examin the location where the “//” appears. We find that if the URL starts with “HTTP”, that means the “//” should appear in the sixth position. However, if the URL employs “HTTPS” then the “//” should appear in seventh position.
# 

# In[11]:


countDoubleSlash = lambda x : x.count('//')


# ##### 05. Adding Prefix or Suffix Separated by (-) to the Domain
# The dash symbol is rarely used in legitimate URLs. Phishers tend to add prefixes or suffixes separated by (-) to the domain name so that users feel that they are dealing with a legitimate webpage. For example http://www.Confirme-paypal.com/.
# 

# In[12]:


countHyphen = lambda x : x.count('-')


# ##### 06. Sub Domain and Multi Sub Domains
# Let us assume we have the following link: http://www.hud.ac.uk/students/. A domain name might include the country-code top-level domains (ccTLD), which in our example is “uk”. The “ac” part is shorthand for “academic”, the combined “ac.uk” is called a second-level domain (SLD) and “hud” is the actual name of the domain. To produce a rule for extracting this feature, we firstly have to omit the (www.) from the URL which is in fact a sub domain in itself. Then, we have to remove the (ccTLD) if it exists. Finally, we count the remaining dots. If the number of dots is greater than one, then the URL is classified as “Suspicious” since it has one sub domain. However, if the dots are greater than two, it is classified as “Phishing” since it will have multiple sub domains. Otherwise, if the URL has no sub domains, we will assign “Legitimate” to the feature. 
# 

# In[13]:


countDots = lambda x: x.count('.')


# ##### 07. num of delimeters:
# [';','_','?','=','&']

# In[14]:


def countDelimeters(x):
    count = 0
    for delim in [';','_','?','=','&']:
        count += x.count(delim)
    return count


# ##### 08. subdirectory count

# In[15]:


countSubDirectory = lambda x : len(re.findall(r"[\s/\s]", x))


# ##### 09. query count

# In[16]:


def countQueries(x):
    if not x:
        return 0
    else:
        return len(x.split('&'))


# ##### 10. Alexa Global Rank

# In[17]:


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


# ##### 11. Domain Registration Length
# Based on the fact that a phishing website lives for a short period of time, we believe that trustworthy domains are regularly paid for several years in advance. In our dataset, we find that the longest fraudulent domains have been used for one year only. 
# 

# In[18]:


to_datetime = lambda x : datetime(int(x.getText()[:4]), int(x.getText()[5:7]), int(x.getText()[8:]))


# In[19]:


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


# ##### Using URL Shortening Services “TinyURL”
# URL shortening is a method on the “World Wide Web” in which a URL may be made considerably smaller in length and still lead to the required webpage. This is accomplished by means of an “HTTP Redirect” on a domain name that is short, which links to the webpage that has a long URL. For example, the URL “http://portal.hud.ac.uk/” can be shortened to “bit.ly/19DXSk4”.
# 

# ##### URL of Anchor
# An anchor is an element defined by the 'a' tag. This feature is treated exactly as “Request URL”.

# In[20]:


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
    features.append(alexaGlobalRank(x))
    features.append(domainRegistrationLength(x))
    return features


# def generateTokens(x):
#     allTokens = []
#     tokenSlash = x.split('/')
#     for ts in tokenSlash:
#         tokensHyphen = ts.split('-')
#         for th in tokensHyphen:
#             tokensDot = th.split('.')
#             allTokens += tokensDot
#     return list(set(allTokens))

# In[ ]:





# In[21]:


agr = pd.read_csv('AlexaGlobalRank.csv')


# In[22]:


drl = pd.read_csv('DomainRegistrationLength.csv')


# In[ ]:





# In[23]:


featureset = pd.DataFrame(dataset['URL'].copy())


# In[24]:


featureset.head()


# In[25]:


featureset['length'] = featureset['URL'].apply(length)


# In[26]:


featureset['isIp'] = featureset['URL'].apply(isIp)


# In[27]:


featureset['countAt'] = featureset['URL'].apply(countAt)


# In[28]:


featureset['countDoubleSlash'] = featureset['URL'].apply(countDoubleSlash)


# In[29]:


featureset['countHyphen'] = featureset['URL'].apply(countHyphen)


# In[30]:


featureset['countDots'] = featureset['URL'].apply(countDots)


# In[31]:


featureset['countDelimeters'] = featureset['URL'].apply(countDelimeters)


# In[32]:


featureset['countSubDirectory'] = featureset['URL'].apply(countSubDirectory)


# In[33]:


featureset['countQueries'] = featureset['URL'].apply(countQueries)


# In[34]:


featureset['alexaGlobalRank'] = agr['alexaGlobalRank'].apply(lambda x : x**(-1))


# In[35]:


featureset['domainRegistrationLength'] = drl['domainRegistrationLength']


# In[ ]:





# In[ ]:





# In[36]:


featureset['label'] = dataset['Label']


# In[37]:


featureset.head()


# In[40]:


featureset.to_csv('featureset.csv', index=False)


# In[ ]:




