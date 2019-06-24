import pyshark
import collections


def sniffer_function(filename, arp_lines_queue, interface, evt):
    """
    Sniff on file or on network, parse data through this flow and put a dico in a queue
    """

    if filename is not None:
        cap = pyshark.FileCapture(filename, display_filter='arp')   #Apply display filter before reading
    else:
        cap = pyshark.LiveCapture(interface, bpf_filter='arp')  #Apply BPF filter on the cap before reading

    for pkt in cap:
        dico = dict()                               #Setup a dictionary as 'dico'
        if hasattr(pkt, 'arp'):                     #If captured packet is an arp packet
            dico['ip'] = pkt.arp.src_proto_ipv4     #Store IP address as 'ip'
            dico['mac'] = pkt.arp.src_hw_mac        #Store MAC address as 'mac'
            arp_lines_queue.put(dico)               #Put the 'dico' in a queue 
    
    evt.set()