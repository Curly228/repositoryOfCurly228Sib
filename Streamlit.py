from math import tanh

import dns.resolver
import requests
import streamlit as st

from urllib.parse import urlparse
from dns import resolver, rdatatype

def verifyTls(url):
    if url.scheme == 'https':
        return 1
    elif url.scheme == 'http':
        return 0
    return 0

def verifySubDomains(url):
    result = 0
    try:
        splitHost = url.hostname.split('.')
        subDomain = splitHost[-2] + "." + splitHost[-1] + "\n"
        file = open('static/top-1000000-domains', 'r')
        for line in file:
            if subDomain == line:
                result = 1
    except Exception as err:
        result = 0
    finally:
        return result

def verifyPhishingFramework(url):
    result = 0
    try:
        requests.get(f'{url.scheme}://{url.hostname}:3333/', timeout=2)
    except Exception as err:
        result = 1
    finally:
        return result

def thNormalizer(x, shift, factor):
    return tanh((x + shift) * factor) * 0.5 + 0.5

def verifyDnsTags(url):
    verification_tags = ("facebook-domain-verification", "google-site-verification", "apple-domain-verification",
                         "google-site-verification", "yandex-verification", "have-i-been-pwned-verification",
                         "mailru-verification", "_globalsign-domain-verification", "wmail-verification")
    result = 0
    try:
        try:
            answer = resolver.resolve('.'.join(url.hostname.split('.')[-2:]), rdtype=rdatatype.TXT,
                              raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return 0
        intersection_counter = 0
        for tag in verification_tags:
            if tag in '$$$'.join([str(record) for record in answer.rrset or []]):
                intersection_counter += 1
        result= thNormalizer(intersection_counter, 0, 0.8)
    except Exception as err:
        result = 0
    finally:
        return result


def verifyDigitCount(url):
    result = 0
    try:
        temp = 0
        digits_count = temp
        for symbol in url.hostname:
            if symbol.isdigit():
                digits_count += 1
    except Exception as err:
        return 0
    finally:
        return thNormalizer(digits_count, -4, -0.5)



url_string = st.text_input('Введите сайт:')
# print('Введите сайт:\n')
url = urlparse(url_string)

st.write("url_string:", url_string)
st.write("url", url)
st.write("url.hostname", url.hostname)

result = {"verifyTLS": verifyTls(url)}
result.update({"verifyDomain": verifySubDomains(url)})
result.update({"verifyPhishingFramework": verifyPhishingFramework(url)})
result.update({"verifyDnsTags": verifyDnsTags(url)})
result.update({"verifyDigitCount": verifyDigitCount(url)})
st.write("Результат проверки сайта на фишинг: ")
st.write(result)

percentResult = 0
for value in result.values():
    percentResult+=value
percentResult/= len(result.keys())


st.write("Вероятность не принадлежности сайта к фишингу", percentResult)
