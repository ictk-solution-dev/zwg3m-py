import sys
import os
import time
from time import gmtime, strftime, localtime

import numpy as np

import json
import csv

import zwg3m

#===============================================================================
json_pub = './pub.json'
json_zwg3m = './zwg3m.json'

sta_ssid = None # Station Mode SSID
sta_pw = None # PassPhrase
aws_ep = None # End Point = AWS Host URL
aws_pn = None # Port Number
aws_tn = None # Thing Name
aws_cid = None # Client ID

mqtt_topic = None
mqtt_qos = None
mqtt_payload = None

#===============================================================================
def main():

  global mqtt_topic
  global mqtt_qos
  global mqtt_payload

     
  os.chdir(os.path.dirname(os.path.realpath(__file__))) 
  if os.path.isfile(json_pub) == False:
    print("Error : Cannot find pub.json")
    sys.exit(1)

  #--- JSON -------------------------------------------------------------------- 
  with open(json_pub, mode='r') as jf_pub:
    jf_pub_data = json.load(jf_pub)
  
  mqtt_topic = jf_pub_data["TOPIC"]
  mqtt_qos = jf_pub_data["QOS"]
  mqtt_payload = jf_pub_data["PAYLOAD"]


  #--- Connect to ZWG3M --------------------------------------------------------
  dev = zwg3m.zwg3m()
  pl = dev.getList()

  if len(pl)<1:
    print("Error : Cannot find COM port")
    sys.exit(1)


  Port = None
  if os.path.isfile(json_zwg3m) == True:
    with open(json_zwg3m, mode='r') as jf:
      Port = json.loads(json.load(jf))['Port']

      if Port in [x[0] for x in pl]:
        pass
      else:
        Port = None

  if Port == None:
    for n in range(len(pl)):
      print('{}: {}'.format(n, pl[n]))
    print('\n')
    n = int(input('Select Port:  '))
    dev.open(pl[n][0])

    data = {'Port':'{}'.format(pl[n][0])}
    jdata = json.dumps(data, indent=2)
    with open(json_zwg3m, mode='w') as jf:
      json.dump(jdata, jf, indent=2)
  else:
    dev.open(Port)

  dev.publish(mqtt_topic, mqtt_qos, mqtt_payload)

  return


#===============================================================================
if __name__ == "__main__":
  main()