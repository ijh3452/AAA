import argparse
import logging
import Queue
import collections
import ConfigParser
import os
import socket
import random
import gi
gi.require_version('Notify', '0.7')
from gi.repository import Notify
from multiprocessing import Process, Queue as MPQueue, Event

import netifaces

from sniffer import sniffer_function
from detection import compare_detection


if os.getuid() != 0:    #Check to see if the user is root
    exit("Error: root permission is required to run this program !")    #If not root send error message and exit
print("AAA is running")     #If root print AAA is running
FORMAT = "%(asctime)-15s %(message)s"   #Format time
logging.basicConfig(filename='AAA.log', filemode='a', level=logging.INFO, format=FORMAT)    #Log the event in the log file


parser = argparse.ArgumentParser(description='AAA')
parser.add_argument('-f', '--file', default=None, type=argparse.FileType('r'), help="Specify file to analyse")  #Arguments to specify file including help message
parser.add_argument('-i', '--interface', default=None, type=str, help="Specify interface eth0|lo|eth1 ...")     #Arguments to specify interface including help message
args = parser.parse_args()

config = ConfigParser.ConfigParser()    #Set config variable for the configuration file    
if os.path.exists('AAA.cfg'):   #if the configuration file exists in the specified path
    config.read('AAA.cfg')      #read the configuration file
    conf_dico = collections.defaultdict(lambda: collections.defaultdict())  #set up container to store data from config file
    for section in config.sections():   #Set up system name in '[]' as section in config file
        for item in config.options(section):    #Set up IP:MAC addresses as item in config file
            conf_dico[section][item] = config.get(section, item)    #get name of the system and it IP:MAC pairings
else:
    exit("Error : can't open AAA.cfg file !")   #Display error message and exit
    logging.info("Error : can't open AAA.cfg file !")   #Log the error message in the log file


from pyshark.packet import layer

#Reading the protocol layer of the packet
class LayerFieldsContainer(layer.LayerFieldsContainer): 
    def __new__(cls, main_field, *args, **kwargs):
        if hasattr(main_field, 'get_default_value'):     
            obj = str.__new__(cls, main_field.get_default_value(), *args, **kwargs)
        else:
            obj = str.__new__(cls, main_field, *args, **kwargs)
        obj.fields = [main_field]
        return obj
layer.LayerFieldsContainer = LayerFieldsContainer   #Store layer fields in a container


def notif(msg):
    Notify.init("AAA")  #Returns the application name
    notice = Notify.Notification.new("Critical ! ARP spoofing detected", msg) #Create new notification with msg and stored as 'notice'
    notice.set_urgency(2) #Set the notice urgency
    notice.show()   #Show the notice in the pop-up notification
    logging.info(msg)   #Log the msg in the log file



def main():
    if args.file is None:
        if args.interface is None:
            parser.error('required parameters : -i/--interface INTERFACE')  #Error message if interface argument is not given
        else:
            interfaces = netifaces.interfaces() #Store the interface identifiers of the machine in 'interfaces'
            if args.interface not in interfaces:    #If the interface argument does not include in 'interfaces'
                print('ERROR: please specify a valid interface : \n%s' % ' | '.join(interfaces))    #Print erroe message
                return

    arp_lines_queue = MPQueue() #Return arp packet information in new multiprocessing queue
    decision_queue = MPQueue()  #Return detected spoof_info in new multiprocessing queue
    producer_evt = Event()  #Return new producer_evt object
    consumer_evt = Event()  #Return new consumer_evt object

    
    sniffer = Process(name='sniffer', target=sniffer_function, args=(args.file, arp_lines_queue, args.interface, producer_evt))     #Set multiprocess sniffer
    worker = Process(name='worker', target=compare_detection, args=(arp_lines_queue, conf_dico, decision_queue, producer_evt, consumer_evt))    #Set multiprocess worker

    sniffer.start() #Start sniffer process
    worker.start()  #Start worker process

    is_attacked = False     #Set default is_attacked as False
    while True:
        try:
            spoof_info, cpt = decision_queue.get(timeout=1)     #Get the spoofed info from the decision queue
        except Queue.Empty:
            if consumer_evt.is_set():
                break
            else:
                continue
        #Format Alert msg with Attacker and Victims information
        msg = "Alert :\n[Attacker's ip/mac : %s/%s]\n[Victim's (%s) ip/mac : %s/%s]\n" \
              % (spoof_info['attacker_ip'],
                 spoof_info['attacker_mac'],
                 spoof_info['victim'],
                 spoof_info['victim_ip'],
                 spoof_info['victim_mac'])
        notif(msg)  #Add the msg in the notification function
        

    sniffer.join()  #Concatnate the sniffer arguments
    worker.join()   #Concatnate the worker arguments

if __name__ == '__main__':
    main()  #Execute main function
