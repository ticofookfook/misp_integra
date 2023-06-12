import time
import json
import urllib3
import re
import os
from pymisp import PyMISP
import logging
import logging.handlers
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def follow(thefile):
    thefile.seek(0, 2)
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line

def valid_ip(address, private):
    from socket import inet_aton
    splited = address.split('.')
    if str(splited[0] + splited[1]) not in private:
        try:
            inet_aton(address)
            return True
        except:
            return False

if __name__ == '__main__':
    logger = logging.getLogger('misp_related')
    logger.setLevel(logging.INFO)
    handler = logging.handlers.SysLogHandler(address=('127.0.0.1', 514))
    logger.addHandler(handler)

    danese = ['8.8.8.8', '8.8.4.4']
    private_ips = ['192168', '169254']
    private_ips.extend([f'10{x}' for x in range(0, 256)])
    private_ips.extend([f'172{x}' for x in range(16, 32)])

    if not os.path.exists('/dados/volumes/single-node_wazuh_integrations/_data/misp_etc/'):
        os.makedirs('/dados/volumes/single-node_wazuh_integrations/_data/misp_etc/')

    with open('/dados/volumes/single-node_wazuh_integrations/_data/misp_etc/searched.ips', 'a+') as f:
        for ip in danese:
            if ip not in f.read().split('\n'):
                f.write(f'{ip}\n')

    #chave de conecção com misp!
    misp_url = '<DNS-OU-IP_MISP>'
    misp_key = '<CHAVE-API-MISP>'
    misp_verifycert = False
    misp = PyMISP(misp_url, misp_key, misp_verifycert)
    
    
    regex_ip = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    #Pegando registros de logs do ossec OBS: o regex foi feito para esta ISO! 
    logfile = open("/var/ossec/logs/archives/archives.log", "r", encoding="ISO-8859-1")
    loglines = follow(logfile)
    for line in loglines:
        all_ips = re.findall(regex_ip, line)
        for ip in all_ips:
            misp_etc_path = '/var/ossec/integrations/misp_etc/'
            searched_ips_file = 'searched.ips'
            if ip not in danese and valid_ip(ip, private_ips):
                #verifica se a pasta misp_etc exist e se o arquivo searched.ips esta nela
                if not os.path.exists(misp_etc_path):
                    os.makedirs(misp_etc_path)
                searched_ips_file_path = os.path.join(misp_etc_path, searched_ips_file)
                if not os.path.exists(searched_ips_file_path):
                    with open(searched_ips_file_path, 'w') as f:
                        pass
                #Escrevendo se o ip for valido e não for um ip dns exemplo: danese = ['8.8.8.8', '8.8.4.4']
                f = open('/var/ossec/integrations/misp_etc/searched.ips', 'r+')
                if ip not in f.read().split('\n'):
                    f.write(f'{ip}\n')
                    f.close()
                misp_response = misp.direct_call('/attributes/restSearch', {"value": ip})
                print("misp respondeu")
                print(misp_response)
                if len(misp_response['Attribute']) > 0:
                     log = json.dumps({
                        "value": ip,
                        "occurrences": len(misp_response['Attribute']),
                        "event_name": [x['Event']['info'] for x in misp_response['Attribute'][-1:]],
                        "event_ids": [x['event_id'] for x in misp_response['Attribute'][-5:]],
                        "log_entry": str(line).strip(),
                        "misp_manager": "IPDOMISP"
                    })
                     logger.info(log)
