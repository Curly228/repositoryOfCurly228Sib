from urllib.parse import urlparse


def verifyTls(url):
    result = 0
    if url.scheme == 'https':
        result = "YES"
    elif url.scheme == 'http':
        result = "NO"
    return result


print('Введите сайт:\n')
url = urlparse(input())

result = {"TLS" : verifyTls(url)}

print("Результат проверки сайта на фишинг ")
print(result)
