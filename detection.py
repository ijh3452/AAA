import Queue
import traceback
import commands


def find_ip(attacker_mac, victim_ip):
    status, ip = commands.getstatusoutput("arp -n | grep -v %s |grep %s | awk '{print $1}'" % (victim_ip, attacker_mac))
    return ip


def compare_detection(arp_lines_queue, config_dico, decision_queue, prod_evt, evt):
    """
    this function puts alert messages in queue if it finds different mac for same IP addressess between config file.
    :return: dict()
    """
    spoof_info = dict()
    cpt = 0
    while True:
        try:
            item = arp_lines_queue.get(timeout=1)   #Information sniffed from the arp packet is set as 'item'
        except Queue.Empty:
            if prod_evt.is_set():
                break
            else:
                continue
        for host, info in config_dico.items():
            if host == "network":
                continue
            if item['ip'] == info['ip']:
                if item['mac'].lower() != info['mac'].lower():
                    spoof_info['attacker_ip'] = find_ip(item['mac'], info['ip'])
                    spoof_info['attacker_mac'] = item['mac']
                    spoof_info['victim'] = host
                    spoof_info['victim_ip'] = info['ip']
                    spoof_info['victim_mac'] = info['mac']
                    cpt += 1
                    decision_queue.put((spoof_info, cpt))   #Put the dictionary in a queue
            else:
                continue
    evt.set()
