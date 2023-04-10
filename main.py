import requests

from urllib.parse import urlparse

from urllib3.exceptions import ConnectTimeoutError


def verifyTls(url):
    if url.scheme == 'https':
        return "YES"
    elif url.scheme == 'http':
        return "NO"
    return "NO"


def verifySubDomains(url):
    splitHost = url.hostname.split('.')
    subDomain = splitHost[1] + "." + splitHost[2] + "\n"
    file = open('static/top-1000000-domains', 'r')
    for line in file:
        if subDomain == line:
            return "YES"

    return "NO"


def verifyPhishingFramework(url):
    result = "NO"
    try:
        requests.get(f'{url.scheme}://{url.hostname}:3333/', timeout=2)
    except Exception as err:
        result = "YES"
    finally:
        return result


print('Введите сайт:\n')
# url = urlparse(input())
url = urlparse("https://drive.google.com/drive/folders/1Y_0bynWBxCengUpb64ycYqlWqq5pyM2E")

result = {"verifyTLS": verifyTls(url)}

result.update({"verifyDomain": verifySubDomains(url)})

result.update({"verifyPhishingFramework": verifyPhishingFramework(url)})

print("Результат проверки сайта на фишинг ")
print(result)
