import requests
from bs4 import BeautifulSoup
import socket
import sys
import re
import time
import hashlib

def get_ip_history(domain):
    print("[.] Получаем историю IP через viewdns.info ...")
    url = f"https://viewdns.info/iphistory/?domain={domain}"
    headers = {'User-Agent': 'Mozilla/5.0'}
    r = requests.get(url, headers=headers)
    soup = BeautifulSoup(r.text, 'html.parser')
    ips = set()
    for tr in soup.find_all('tr'):
        tds = tr.find_all('td')
        if len(tds) >= 2 and re.match(r'\d+\.\d+\.\d+\.\d+', tds[0].text):
            ips.add(tds[0].text.strip())
    ips = list(ips)
    print(f"[+] Найдено {len(ips)} IP: {ips}")
    return ips

def parse_raw_http(filename):
    with open(filename) as f:
        lines = f.read().split('\n')
    method, path, _ = lines[0].split()
    headers = {}
    body = ""
    i = 1
    # Parse headers
    while i < len(lines) and lines[i]:
        k, v = lines[i].split(':', 1)
        headers[k.strip()] = v.strip()
        i += 1
    # Skip empty line
    i += 1
    # Everything after — body
    body = '\n'.join(lines[i:]).strip()
    return method, path, headers, body

def make_request(ip, domain, method, path, headers, body, use_https=True):
    url = f"{'https' if use_https else 'http'}://{ip}{path}"
    # Подменяем Host на нужный
    headers = headers.copy()
    headers['Host'] = domain
    # Не даём requests сам резолвить, иначе не подменим ip
    try:
        s = requests.Session()
        s.trust_env = False
        resp = s.request(method, url, headers=headers, data=body, timeout=8, verify=False)
        return resp
    except Exception as e:
        return None

def get_domain_from_headers(headers):
    # Host: ....
    for k, v in headers.items():
        if k.lower() == "host":
            return v.split(":")[0]
    return None

def compare_responses(orig, test):
    if not test:
        return 0, []
    score = 0
    details = []
    if orig.status_code == test.status_code:
        score += 1
        details.append("Код совпал")
    if 'Server' in orig.headers and 'Server' in test.headers and orig.headers['Server'] == test.headers['Server']:
        score += 1
        details.append("Server совпал")
    l0 = len(orig.content)
    l1 = len(test.content)
    if l0 and abs(l0 - l1) / max(l0, 1) < 0.10:
        score += 1
        details.append("Длина тела ±10%")
    h0 = hashlib.md5(orig.content[:2048]).hexdigest()
    h1 = hashlib.md5(test.content[:2048]).hexdigest()
    if h0 == h1:
        score += 2
        details.append("MD5 первых 2кб совпал")
    # Можно добавить ключевые слова при желании
    return score, details

def main(reqfile):
    method, path, headers, body = parse_raw_http(reqfile)
    domain = get_domain_from_headers(headers)
    if not domain:
        print("Host header not найден в запросе!")
        sys.exit(1)

    print(f"[.] Эталонный запрос к {domain}...")
    use_https = headers.get('Referer', '').startswith('https') or headers.get('Origin', '').startswith('https') or True
    orig = make_request(domain, domain, method, path, headers, body, use_https=use_https)
    if not orig:
        print("[-] Ошибка запроса к оригиналу.")
        sys.exit(1)
    print(f"Код={orig.status_code}, Server={orig.headers.get('Server', '')}, Body len={len(orig.content)}")

    iplist = get_ip_history(domain)
    if not iplist:
        print("Нет исторических IP, выход.")
        sys.exit(0)

    print("[.] Проверяем айпишники ...")
    for ip in iplist:
        print(f"\n[.] Проверяю {ip} ...", end=' ')
        try:
            time.sleep(1)
            test = make_request(ip, domain, method, path, headers, body, use_https=use_https)
            score, details = compare_responses(orig, test)
            if score >= 3:
                print(f"Похоже ({score}): {', '.join(details)}")
            else:
                print(f"Нет совпадения ({score})")
        except Exception as e:
            print(f"Ошибка: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] not in ["-r", "--request"]:
        print("Использование: python3 bypass.py -r req.txt")
        sys.exit(1)
    main(sys.argv[2])
