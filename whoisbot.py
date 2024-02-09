
#!/usr/bin/python3

from ipwhois import IPWhois
from sys import argv
from flask import Flask, request
from requests.packages.urllib3.util.retry import Retry
import requests.packages.urllib3, requests, json, time, datetime, re, os, csv
from binascii import hexlify
from collections import Counter
import pycountry
import threading
from apscheduler.schedulers.background import BlockingScheduler


whitelist_ip = ''
whitelist_description = ''
whitelist_country = ''
botEmail = "-@webex.bot"
#botEmail = "-@webex.bot"
accessToken = "-"
#accessToken = '-'
headers = {"Authorization": "Bearer %s" % accessToken, "Content-Type": "application/json", 'Accept' : 'application/json'}

now = datetime.datetime.now()
now = now + datetime.timedelta(days=0, seconds=0, microseconds=0, milliseconds=0, minutes=0, hours=9, weeks=0)

fPath_working = os.getcwd()

def GetInfo(ip):
    try:
        w = IPWhois(ip).lookup_rdap()
        print('lookup succeeded')
    except:
        print('lookup failed')
        return {'state' : False}
    _net = w["network"]
    _obj = w["objects"]
    red = "\x1b[0;31m"
    cyan = "\x1b[0;36m"
    end = "\x1b[0m"

    # ASN
    _asn = {
        "asn": "ASN",
        "asn_cidr": "CIDR",
        "asn_country_code": "Country code",
        "asn_date": "Date",
        "asn_description": "Description",
        "asn_registry": "Registry"
    }

    dic_ret = {}
    for k, v in _asn.items():
        dic_ret[f'{v}'] = f'{w[k]}'
    return {'state' : True, 'whois' : dic_ret}
    
def SendMessage(payload, msg):
    payload["text"] = str(msg)
    response = requests.request("POST", "https://webexapis.com/v1/messages", data=json.dumps(payload),
                                    headers=headers)
    response = json.loads(response.text)
    return {'messageId' : response['id']}

def ModifyMessage(payload, msg, messageId):
    payload["text"] = str(msg)
    requests.request("PUT", "https://webexapis.com/v1/messages/{}".format(messageId),
                                                data=json.dumps(payload), headers=headers)
    
def SendFile(fullPath, roomId, text=""):
    print('send the file')
    with open(fullPath, 'rb') as f:
        cmd = f"""curl --request POST\
         --header "Authorization: Bearer {accessToken}"\
         --form "files=@{fullPath};type=image/png"\
         --form "roomId={roomId}"\
         --form "text={text}"\
         https://webexapis.com/v1/messages"""
        os.system(cmd)

def LoadWhitelist(padding = '_'):
    global whitelist_ip, whitelist_description, whitelist_country, fPath_working
    os.system(f'cp {fPath_working}/cdns.txt {fPath_working}/cdns{padding}.txt')
    os.system(f'cp {fPath_working}/descriptions.txt {fPath_working}/descriptions{padding}.txt')
    os.system(f'cp {fPath_working}/countries.txt {fPath_working}/countries{padding}.txt')
    print('@@' + f'cp cdns.txt cdns{padding}.txt')
    time.sleep(1)
    with open(f'{fPath_working}/cdns{padding}.txt', 'r') as f:
        whitelist_ip = [x for x in f.read().split('\n') if len(x) > 0]
    with open(f'{fPath_working}/descriptions{padding}.txt', 'r') as f:
        whitelist_description = [x for x in f.read().split('\n') if len(x) > 0]
        print('[*] description : ' + str(whitelist_description))
    with open(f'{fPath_working}/countries{padding}.txt', 'r') as f:
        whitelist_country = [x for x in f.read().split('\n') if len(x) > 0]
    os.system(f'rm {fPath_working}/cdns{padding}.txt')
    os.system(f'rm {fPath_working}/descriptions{padding}.txt')
    os.system(f'rm {fPath_working}/countries{padding}.txt')
app = Flask(__name__)


@app.route('/', methods=['POST'])
def get_tasks():
    global fPath_working
    data = request.json.get('data')
    email, roomId, messageId = data['personEmail'], data['roomId'], data['id']
    
    if email == botEmail:
        return ("")

    payload = {"roomId": roomId}
    response = json.loads(
    requests.request("GET", "https://api.ciscospark.com/v1/messages/{}".format(messageId), headers=headers).text)
    
    try:
    	msgs = response['text'].strip().split('\n')
    except:
        SendMessage(payload, '[*] 명령어를 입력해주세요.')
        return ({'status': 'Failed'})
    
    header = msgs[0]
    
    regex_whitelist = r"/(up|down) (ip|description|country)"
    regex_ip = r'(?:\d{1,3}\.){3}\d{1,3}'
    if header.startswith('/help'):
        menu = '[*] IP 조회'
        menu += '● \' [조회 IP] [option]\'\n'
        menu += '● 옵션 : \' --excel | -e\' : 결과를 엑셀파일로 생성 \'\n'
        menu += '\n[*] 화이트리스트 다운/업로드\n'
        menu += '● \' /[up | down]  [ip | country | description] \'\n'
        menu += '● 화이트리스트 파일 업로드시 바로 적용됩니다.\n'
        menu += '\n[*] 파일 양식\n'
        menu += '● IP : ip;;설명\n'
        menu += '● Description : description;;설명\n'
        menu += '● Country : country\n'
        SendMessage(payload, menu)
    elif re.match(regex_whitelist, header):
        action, target = re.findall(regex_whitelist, header)[0]
        if action == 'down':
            if target == 'ip':
            	SendFile('cdns.txt', roomId,'')
            elif target == 'description':
                SendFile('descriptions.txt', roomId,'')
            elif target == 'country':
                SendFile('countries.txt', roomId,'')
        elif action == 'up':
            if not 'files' in response:
                SendMessage(payload, "[*] 파일을 업로드 하세요.")
            if target == 'ip':
                fPath = 'cdns.txt'
            elif target == 'description':
                fPath = 'descriptions.txt'
            elif target == 'country':
                fPath = 'countries.txt'
            files = response['files'][0]
            
            response = requests.request("GET", files, headers=headers)
            response.raise_for_status()
            response.encoding="UTF-8"
            
            with open(fPath, 'w', encoding="UTF-8") as f:
                f.write(response.text)

            LoadWhitelist(email)
            SendMessage(payload, f"[*] 화이트리스트 {target} 적용 완료.")
    elif re.search(regex_ip, response['text']):
        list_ip = re.findall(regex_ip, ' '.join(msgs))
        list_ip = list(dict(Counter(list_ip)).keys())
        opt_format = re.findall('(?:--excel|-e)', ''.join(msgs))
        SendMessage(payload, '[*] 입력한 IP를 조회합니다. [{}개]'.format(len(list_ip)))
        outputs_trusted = []
        outputs_censored = []
        outputs_ip = []
        excel_ip = []
        outputs_failed = []
        extend = 3
        totalLen = len(list_ip)
        progress = 1
        if totalLen > 20:
        	messageId = SendMessage(payload, '[*] 진행률 : 0% [ 0 / {} ] \n'.format(totalLen) + '▷ ' * 10 * extend)['messageId']
        time_start = time.time()
        for idx in range(len(list_ip)):
            ip = list_ip[idx]
            if idx + 1 > progress * (totalLen/10) and progress < 9 and totalLen > 20:
                ModifyMessage(payload, '[*] 진행률 : {}% [ {} / {} ] ; {} seconds\n'.format(round(idx/totalLen, 2)*100, idx+1, totalLen, round(time.time() - time_start, 2)) + '▶ ' * progress * extend + '▷ ' * (10 - progress) * extend, messageId)
                progress += 1
            result = GetInfo(ip)
            #time.sleep(0.2)
            if not result['state']:
                outputs_failed.append(ip)
                continue
            if result['whois']['Description'] == 'None' or result['whois']['Country code']:
                r_whois = os.popen('whois ' + str(ip)).read()
                wis_des = re.findall('OrgName\s*:\s*(.+)\n', r_whois)
                wis_cty = re.findall('Country\s*:\s*(.+)\n', r_whois)
                if len(wis_des) > 0:
                	result['whois']['Description'] = re.findall('OrgName\s*:\s*(.+)\n', r_whois)[0]
                if len(wis_cty) > 0:
                	result['whois']['Country code'] = re.findall('Country\s*:\s*(.+)\n', r_whois)[0]
            try:
                ipInfo = result['whois']

                censored = 0

                country = pycountry.countries.get(alpha_2=ipInfo['Country code']).name

                output = ''
                censor_msg = ''

                op  = f'IP : {ip} '
                for wl in whitelist_ip:
                    cdn, description = wl.split(';;')
                    if ip.startswith(cdn):
                        censor_msg = cdn + f' ({description})'
                        op = "● " + op + ' --> [' + censor_msg + ']'
                        censored = 1
                        break
                output += output + op + '\n'

                op = f'Country : {country} '
                for ctry in whitelist_country:
                    ctry = ctry.replace(' ', '').lower()
                    if ctry in country.replace(' ', '').lower():
                        censor_msg = '[화이트리스트]'
                        op = "● " + op + ' --> [화이트리스트]'
                        censored = 1
                        break
                output = output + op + '\n'

                op = f'Description : {ipInfo["Description"]} '
                for wl in whitelist_description:
                    owner, description = wl.split(';;')
                    owner = owner.replace(' ', '').lower()
                    if owner in ipInfo['Description'].replace(' ', '').lower():
                        censor_msg = owner + f' ({description})'
                        op = "● " + op + ' --> [' + owner + f' ({description})' + ']'
                        censored = 1
                        break
                output = output + op + '\n'

                if not censored:
                    outputs_ip.append(ip)
                    outputs_trusted.append(output)
                else:
                    outputs_censored.append(output)
                excel_ip.append([ip, country, ipInfo["Description"], censor_msg])
            except:
                outputs_failed.append(ip)
                with open('error.txt', 'a') as f:
                    f.write(f'[whois] ' + '아이피 조회 중 예외 발생')
        
        if totalLen > 20:
        	ModifyMessage(payload, '[*] 진행률 : 100% [ {} / {} ] ; {} seconds\n'.format(totalLen, totalLen, round(time.time() - time_start, 2)) + '▶ ' * 10* extend, messageId)
                    
        outputs = ''
        len_trusted = len(outputs_trusted)
        if len_trusted > 0:
            outputs += f"[*] 안전 [ {len_trusted} / {totalLen} ]\n"
            outputs += "\n".join(outputs_trusted)
            
        len_censored = len(outputs_censored)
        if len(outputs_censored) > 0:
            if len(outputs) > 1:
                outputs += "\n\n"
            outputs += f"[*] 위험 [ {len_censored} / {totalLen} ]\n"
            outputs += "\n".join(outputs_censored)
                    
        len_failed = len(outputs_failed)
        if len(outputs_failed) > 0:
            if len(outputs) > 1:
                outputs += "\n\n"
            outputs += f"[*] 룩업 실패 [ {len_failed} / {totalLen} ]\n"
            outputs += "\n".join(outputs_failed)
            
        if len(outputs_trusted) + len(outputs_censored) > 10 :
            with open('list_whois.txt', 'w') as f:
                f.write(outputs)
            SendFile('list_whois.txt', roomId, '')
        else:
        	SendMessage(payload, outputs)
        
        if len(outputs_ip) > 0:
            msg = "***************************\n\n"
            msg += '\n'.join(outputs_ip) + '\n\n'
        else:
            msg = ""
        msg += "***************************\n"
        msg += "\n"
        
        if len(outputs_ip) > 10:
            with open('list_ip.txt', 'w') as f:
                f.write(msg)
            SendFile('list_ip.txt', roomId, '')
        else:
        	SendMessage(payload, msg)
        msg = "[안전 : {} / 전체 : {} ]".format(len(outputs_ip), len(list_ip))
        SendMessage(payload, msg)
            
        
        if len(opt_format) > 0 :
            fullPath = f'{fPath_working}/result.csv'
            excel_ip.insert(0, ['IP', 'Country', 'Description', 'Reason'])
            with open(fullPath, 'w', encoding='utf-8-sig', newline='') as f_write:
                writer = csv.writer(f_write)
                for row in excel_ip:
                    writer.writerow(row)
            SendFile(fullPath, roomId, '')
            os.system('rm -f ' + fullPath)
    else:
        SendMessage(payload, f'-bash: {header}: command not found (Type "/help")')
    return ({'status': 'Success'})


def CallerCheck():
    sched = BlockingScheduler(timezone='Asia/Seoul')
    sched.add_job(CheckAvailability,'interval', minutes=60*24, id='availability')
    #sched.add_job(CheckAvailability,'interval', minutes=1, id='availability')
    sched.start()
    
def CheckAvailability():
    global now, roomId_use
    payload = {"roomId": roomId_use}
    now = datetime.datetime.now()
    now = now + datetime.timedelta(days=0, seconds=0, microseconds=0, milliseconds=0, minutes=0, hours=9, weeks=0)
    SendMessage(payload, "[{}] 상태 체크".format(now.strftime('%Y-%m-%d %H:%M:%S')))

def run():
    print('start')
    LoadWhitelist()
    app.run(host="0.0.0.0", port=8999)
