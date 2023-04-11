from math import tanh

import dns.resolver
import requests
import os
from urllib.parse import urlparse
from dns import resolver, rdatatype



def get_password():
    password = os.environ.get('PASSWORD')
    return password

def verifyTls(url):
    if url.scheme == 'https':
        return 1
    elif url.scheme == 'http':
        return 0
    return 0


def verifySubDomains(url):
    splitHost = url.hostname.split('.')
    subDomain = splitHost[-2] + "." + splitHost[-1] + "\n"
    file = open('static/top-1000000-domains', 'r')
    for line in file:
        if subDomain == line:
            return 1

    return 0


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
    try:
        answer = resolver.resolve('.'.join(url.hostname.split('.')[-2:]), rdtype=rdatatype.TXT,
                              raise_on_no_answer=False)
    except dns.resolver.NXDOMAIN:
        return 0

    intersection_counter = 0
    for tag in verification_tags:
        if tag in '$$$'.join([str(record) for record in answer.rrset or []]):
            intersection_counter += 1
    return thNormalizer(intersection_counter, 0, 0.8)

def verifyDigitCount(url):
    temp = 0
    digits_count = temp
    for symbol in url.hostname:
        if symbol.isdigit():
            digits_count += 1

    return thNormalizer(digits_count, -4, -0.5)

#url_string = st.text_input('Введите сайт:')
print('Введите сайт:\n')
url = urlparse(input())
#url = urlparse(url_string)
#url = urlparse("https://drive.google.com/drive/folders/1Y_0bynWBxCengUpb64ycYqlWqq5pyM2E")
# url = urlparse("https://payhubcard.com")


result = {"verifyTLS": verifyTls(url)}

result.update({"verifyDomain": verifySubDomains(url)})

result.update({"verifyPhishingFramework": verifyPhishingFramework(url)})

result.update({"verifyDnsTags": verifyDnsTags(url)})

result.update({"verifyDigitCount": verifyDigitCount(url)})

percentResult = 0

for value in result.values():
    percentResult+=value

percentResult/= len(result.keys())

print("Результат проверки сайта на фишинг ")
#st.write("Результат проверки сайта на фишинг ")
#st.write(result)
#st.write("Вероятность не принадлежности сайта к фишингу")
#st.write(percentResult)
print(result)
print("Вероятность не принадлежности сайта к фишингу")
print(percentResult)
input("Нажмите enter что бы продолжить.")
