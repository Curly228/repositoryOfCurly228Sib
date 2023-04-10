from urllib.parse import urlparse

def verifyTls(url):
    result = "NO"
    if url.scheme == 'https':
        result = "YES"
    elif url.scheme == 'http':
        result = "NO"
    return result


def verifySubDomains(url):
    splitHost = url.hostname.split('.')
    subDomain = splitHost[1] + "."+splitHost[2]+"\n"
    file = open('static/top-1000000-domains', 'r')
    for line in file:
        if subDomain == line:
            return "YES"

    return "NO"

print('Введите сайт:\n')
url = urlparse(input())

result = {"verifyTLS": verifyTls(url)}

result.update( {"verifyDomain": verifySubDomains(url)})


print("Результат проверки сайта на фишинг ")
print(result)
