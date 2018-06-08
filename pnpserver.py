#!/usr/bin/env python
#
# snom multicast telephone discovery
#
#
# Author: Filip Polsakiewicz <filip.polsakiewicz@snom.de>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import socket
import struct
import sys
import re
import ConfigParser
import traceback

from snom_phone import snom_phone
from utils import utils

from optparse import OptionParser

# Script configuration
config = {}

# Multi-Stage configuration
msconfig = {}

# This can be used for multi-step deployments
# Contains mac addresses of the phones which already hit this server
phone_dict = {}

# Multi-Stage deployment status dictionary
multi = {}

def parse(text):
    """Parses the incoming SUBSCRIBE."""
    try:
        lines = text.split('\r\n')
    
        # Line 1 conatains the SUBSCRIBE and our MAC
        new_phone = snom_phone(subs=text)
        new_phone.mac_addr = lines[0][20:32]
        
        # We can read the IP address from line 2
        new_phone.ip_addr = lines[1][17:].split(';')[0].split(':')[0]
	new_phone.sip_port = lines[1][17:].split(';')[0].split(':')[1]
        
        # The other interesting information can be found in line 7
        model_info = lines[6]
        l_model_info = model_info.split(';')
        new_phone.model = l_model_info[3].split('=')[1][1:-1]
        new_phone.fw_version = l_model_info[4].split('=')[1][1:-1]
        print new_phone
    	
        return new_phone
    except:
        # Parsing failed. Probably not a SUBSCRIBE
        print "Parsing failed!"
        (type, value, tb) = sys.exc_info()
        traceback.print_exception(type, value, tb)
        return None

# Phone passed multistage
def phone_done(phone):
    print "Phone %s has finished the multistep deployment process." % phone

# Make sure the multistage list is up-to-date
def update_multistage_list(mac_addr):
    specific = mac_addr in msconfig
    length = 0
    if specific:
        length = len(msconfig[mac_addr])
    else:
        length = len(msconfig['default'])
                     
    if multi[phone.mac_addr]:
        # Phone is already in the list
        current_step = int(multi[phone.mac_addr])
        if current_step == length: # last step reached
            phone_done(phone.mac_addr)
            del multi[phone.mac_addr]
        else:
            current_step = current_step + 1
            print "Next step for phone %s will be %s of %s" % (phone.mac_addr, str(current_step), length)
            multi[phone.mac_addr] = current_step
    else:
        # Phone not in the list -> this should never happen
        print "ERROR: phone is not in the multistage list!!!"
        pass

# Return the correct provisioning url in any case
def get_provisioning_url(model, mac_addr):
    if config['multistage']:
        specific = False
        if mac_addr in msconfig:
            specific = True

        step = get_multistage_step(mac_addr)
        print "Preparing to send configuration for step %s" % step
        if specific:
            update_multistage_list(mac_addr)
            return utils.replace_config_templates(msconfig[mac_addr][str(step)], config, model)
        else:
            update_multistage_list(mac_addr)
            return utils.replace_config_templates(msconfig['default'][str(step)], config, model)
        
    else:
        return config['prov_uri']

# Get the current multistage step
def get_multistage_step(phone):
    if phone in multi:
        return multi[phone]
    else:
        multi[phone] = 1
        return 1

prov_uri = None
parser = OptionParser()
parser.add_option('-u', '--url', action="store", dest="prov_uri", help="URI of the provisioning server")
parser.add_option('-c', '--config', action="store", dest="config", help="Deployment configuration file")
parser.add_option('-l', '--local-ip', action="store", dest="local_ip", help="Local IP address")
parser.add_option('-p', '--local-port', action="store", dest="local_port", help="Local port", default=5060)
parser.add_option("-v", "--verbose",
                  action="store_true", dest="verbose", default=False,
                  help="make lots of noise")

(options, args) = parser.parse_args()

print """                                                                                
                                                                                
                                                                                
      .ijjt;     ..... :tjt:             LLLi    ..... .ijt,    :tjt:             
    .LLLLLLLLL,  LLLLtLLLLLLL      ,ft   LLLLL.  LLLLLjLLLLLL .LLLLLLL            
    LLLLLLLLLLLt LLLLLLLLLLLL;   :LLLj   LLLLLL  fLLLLLLLLLLLLLLLLLLLLt           
   tLLLf,,iLLLt  LLLLLLfLLLLLf. :LLLLf    :LLLLj fLLLLLffLLLLLLLfLLLLLL           
   LLLL     :t   LLLLL   jLLLf. LLLLL:     :LLLL fLLLL.  :LLLLL   jLLLL           
   LLLLL;.       LLLLt   ,LLLf.;LLLL        LLLL.fLLLL    LLLLj   :LLLL           
   jLLLLLLLLf,   LLLLt   ,LLLf.fLLL;        LLLL:fLLLL    LLLLj   .LLLL           
    LLLLLLLLLLL  LLLLt   ,LLLf.LLLL:  1.1   fLLL:fLLLL    LLLLj   .LLLL           
     ,fLLLLLLLLt LLLLt   ,LLLf.LLLL.        LLLL.fLLLL    LLLLj   .LLLL           
         :iLLLLL LLLLt   ,LLLf.LLLL,       .LLLL fLLLL    LLLLj   .LLLL           
    L;      LLLL LLLLt   ,LLLf.jLLLj      .LLLLf fLLLL    LLLLj   .LLLL           
   iLL:    .LLLL LLLLt   ,LLLf.iLLLL     ;fLLLL; fLLLL    LLLLj   .LLLL           
  tLLLLLjjfLLLL; LLLLt   ,LLLf. LLLLf.   fLLLLf  fLLLL    LLLLj   .LLLL           
   fLLLLLLLLLLf  LLLLt   ,LLLf. ;LLLLL   jLLLt   fLLLL    LLLLj   .LLLL           
    ,LLLLLLLLi   LLLLt   ,LLLf.  iLLLL   tf;     LLLLL    LLLLj   .LLLL           
       :,,:.                      .jLL                                          
"""
print "\nsnom multicast PnP Provisioning Server (mcserv)\n"
print "(c) 2008-2009 snom technology AG\n"
print "=" * 80

config['prov_uri'] = options.prov_uri

# Configuration file has been provided
#
# NOTE: Local (command-line) options overwrite config file
# 
configuration = ConfigParser.ConfigParser()
if options.config:
    print "Reading configuration from %s" % options.config
    configuration.read(options.config) # Fixme: make sure the file exists
    (config, msconfig) = utils.parse_config(configuration, options)

if not config['multistage']:
    print "Provisioning URI is %s\n" % config['prov_uri']

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('224.0.1.75', options.local_port))
mreq = struct.pack('4sl', socket.inet_aton('224.0.1.75'), socket.INADDR_ANY)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

if not options.local_ip and not config['local_ip']:
    config['local_ip'] = utils.get_ip_address()
else:
    config['local_ip'] = options.local_ip

if not "local_port" in config and not config['local_port']:
    config['local_port'] = options.local_port
    
print "Local IP Address is :: %s" % config['local_ip']
print "Local IP Port    is :: %s" % config['local_port']
print "=" * 80

# Main loop
while True:
    subs = sock.recv(10240)
    
    if options.verbose: print subs

    phone = parse(subs)
    
    (call_id, cseq, via_header, from_header, to_header) = utils.get_sip_info(subs, options.verbose)
    
    if phone:
        # Check if on ignore/allow lists
        if config['ignoreall']:
            # Allow the phone?
            if not phone.mac_addr in config['allow_list']:
                print "Phone %s not served as we ignore all phones except for those on the allow list." % phone.mac_addr
                continue
        else:
            # Do we ignore this phone?
            if phone.mac_addr in config['ignore_list']:
                print "Phone %s not served as it is on the ignore list." % phone.mac_addr
                continue
            
        # Create a socket to send data
        print "Generating response ..."
        sendsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
	sendsock.bind(('%s' % config['local_ip'], config['local_port']))

    	# If a phone has been recognized first send 200 OK
        ok_response = "SIP/2.0 200 OK\r\n"
        ok_response += via_header + "\r\n"
        ok_response += "Contact: <sip:" + phone.ip_addr + ":" + phone.sip_port + ";transport=tcp;handler=dum>\r\n"
        ok_response += to_header + "\r\n"
        ok_response += from_header + "\r\n"
        ok_response += "Call-ID: %s\r\n" % call_id
        ok_response += "CSeq: %s SUBSCRIBE\r\nExpires: 0\r\nContent-Length: 0\r\n" % cseq
        
        sendsock.sendto(ok_response, ("%s" % phone.ip_addr, int(phone.sip_port)))

	# Now send a NOTIFY with the configuration URL
        prov_uri = get_provisioning_url(phone.model, phone.mac_addr).strip()

#         if not options.prov_uri:
#             prov_uri = "http://provisioning.snom.com/%s/%s.php?mac={mac}" % (phone.model, phone.model)
#         else:
#             prov_uri = options.prov_uri
#             prov_uri = "%s/%s.htm" % (prov_uri,phone.model)

        (new_to_header, new_from_header) = utils.swap_headers(to_header, from_header)
	notify = "NOTIFY sip:%s:%s SIP/2.0\r\n" % (phone.ip_addr, phone.sip_port)
	notify += via_header + "\r\n"
	notify += "Max-Forwards: 20\r\n"
	notify += "Contact: <sip:%s:%s;transport=TCP;handler=dum>\r\n" % (config['local_ip'], config['local_port'])
	notify += new_to_header + "\r\n"
	notify += new_from_header + "\r\n"
	notify += "Call-ID: %s\r\n" % call_id
	notify += "CSeq: 3 NOTIFY\r\n"
	notify += "Content-Type: application/url\r\n"
	notify += "Subscription-State: terminated;reason=timeout\r\n"
	notify += "Event: ua-profile;profile-type=\"device\";vendor=\"OEM\";model=\"OEM\";version=\"7.1.19\"\r\n"
	notify += "Content-Length: %i\r\n" % (len(prov_uri) + 2)
	notify += "\r\n%s" % prov_uri

	print "Sending NOTIFY with URI :: %s\n" % prov_uri
        if options.verbose: print notify
	sendsock.sendto(notify, ("%s" % phone.ip_addr, int(phone.sip_port)))
	
