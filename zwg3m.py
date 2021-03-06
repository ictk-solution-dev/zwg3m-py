import sys
import serial
from serial.tools import list_ports
import time
import binascii
#===============================================================================




#===============================================================================
class serCommon:
  #-----------------------------------------------------------------------------
  def __init__(self):
    pass

  #-----------------------------------------------------------------------------
  def getList(self):
    self.pl = list(list_ports.comports())
   
    return self.pl

  #----------------------------------------------------------------------------
  def open(self,port):
    cpath = '\\\\.\\' + port
    self.sp = serial.Serial(port=cpath, 
                            baudrate=115200,
                            bytesize=serial.EIGHTBITS,
                            parity=serial.PARITY_NONE,
                            stopbits=serial.STOPBITS_ONE,
                            timeout=None)

    return self.sp

  #-----------------------------------------------------------------------------
  def close(self):
    self.sp.close()


#===============================================================================
class zwg3m(serCommon):
  #-----------------------------------------------------------------------------
  def __init__(self):
    super().__init__()

  #-----------------------------------------------------------------------------
  def set_wifi(self, set, ssid, pw):
    print("wi-fi:",ssid,pw)

    #--- Wi-Fi - SSID ----------------------------------------------------------
    if set == "U":
      ussid=(ssid).encode("UTF-8")
      print(ussid)
      essid=binascii.hexlify(ussid)
      print(essid)
      data = "AT+WIFI_SSID_STA_U=".encode() + essid + '\n'.encode() 
      print(data)     
    else:
      data = "AT+WIFI_SSID_STA=".encode() + ssid.encode() + '\n'.encode()
      
    self.sp.write(data)
    time.sleep(0.01)

    data = self.sp.readline()
    if("SUCCEED\n".encode() == data):
      print("OK")
    else:
      print("Fail")
    data = self.sp.readline()

    #--- Wi-Fi - PassPhrase ----------------------------------------------------
    data = "AT+WIFI_PW_STA=".encode() + pw.encode() + '\n'.encode()
    self.sp.write(data)
    time.sleep(0.01)

    data = self.sp.readline()
    if("SUCCEED\n".encode() == data):
      print("OK")
    else:
      print("Fail")
    data = self.sp.readline()

  #-----------------------------------------------------------------------------
  def set_aws(self, ep, pn, tn, cid):
    print("AWS:",ep,pn,tn,cid)

    #--- End Point -------------------------------------------------------------
    data = "AT+AWS_EP=".encode() + ep.encode() + '\n'.encode()
    self.sp.write(data)
    time.sleep(0.01)

    data = self.sp.readline()
    if("SUCCEED\n".encode() == data):
      print("OK")
    else:
      print("Fail")
    data = self.sp.readline()

    #--- Port Number -----------------------------------------------------------
    data = "AT+AWS_PN=".encode() + str(pn).encode() + '\n'.encode()
    self.sp.write(data)
    time.sleep(0.01)

    data = self.sp.readline()
    if("SUCCEED\n".encode() == data):
      print("OK")
    else:
      print("Fail")
    data = self.sp.readline()

    #--- Thing Name ------------------------------------------------------------
    data = "AT+AWS_TN=".encode() + tn.encode() + '\n'.encode()
    self.sp.write(data)
    time.sleep(0.01)

    data = self.sp.readline()
    if("SUCCEED\n".encode() == data):
      print("OK")
    else:
      print("Fail")
    data = self.sp.readline()

    #--- Client ID -------------------------------------------------------------
    data = "AT+AWS_CID=".encode() + cid.encode() + '\n'.encode()
    self.sp.write(data)
    time.sleep(0.01)

    data = self.sp.readline()
    if("SUCCEED\n".encode() == data):
      print("OK")
    else:
      print("Fail")
    data = self.sp.readline()

  #-----------------------------------------------------------------------------
  def publish(self, topic, qos, payload):

    #--- AWS Publish -----------------------------------------------------------
    data = "AT+AWS_PUB=".encode() + topic.encode() + ','.encode() + str(qos).encode() + ','.encode() + payload.encode() + '\n'.encode()
    self.sp.write(data)
    time.sleep(0.01)

    data = self.sp.readline()
    if("SUCCEED\n".encode() == data):
      print("OK")
    else:
      print("Fail")
    
    data = self.sp.readline()
    time.sleep(0.01)

    data = self.sp.readline()
    if("EVENT:PUB OK\n".encode() == data):
      print("OK")
    else:
      print("Fail")

  #-----------------------------------------------------------------------------
  def subscribe(self, topic, qos):

    #--- AWS Subscribe -----------------------------------------------------------
    data = "AT+AWS_SUB=".encode() + topic.encode() + ','.encode() + str(qos).encode() + '\n'.encode()
    self.sp.write(data)
    time.sleep(0.01)

    data = self.sp.readline()
    if("SUCCEED\n".encode() == data):
      print("OK")
    else:
      print("Fail")
    
    data = self.sp.readline()
    time.sleep(0.01)

    data = self.sp.readline()
    if("EVENT:SUB OK\n".encode() == data):
      print("OK")
    else:
      print("Fail")
  #-----------------------------------------------------------------------------
  def update(self, act, key, ty, val):

    #--- AWS Update -----------------------------------------------------------
    if(ty == 9):
      data = "AT+AWS_UPDATE=".encode() +str(act).encode()+ ','.encode() +key.encode() + ','.encode()+ str(ty).encode()  + ','.encode()+val.encode()+'\n'.encode()
    else:
      data = "AT+AWS_UPDATE=".encode() +str(act).encode()+ ','.encode() +key.encode() + ','.encode()+ str(ty).encode()  + ','.encode()+str(val).encode()+'\n'.encode()

    self.sp.write(data)
    time.sleep(0.01)

    data = self.sp.readline()
    if("SUCCEED\n".encode() == data):
      print("OK")
    else:
      print("Fail")
        
    while True:      
      data = self.sp.read(1)
      n = self.sp.inWaiting()
      if n<1:
        break
      else:            
          data = data + self.sp.readline()
          print(data)
          time.sleep(0.05)

    '''      
    data = self.sp.readline()
    data = self.sp.readline()
    time.sleep(0.01)
    
    data = self.sp.readline()
    if("EVENT:UPDATE Accepted\n".encode() == data):
      print("OK")
    else:
      print("Fail")
    '''

  #-----------------------------------------------------------------------------
  #-----------------------------------------------------------------------------
  def unsubscribe(self, topic):

    #--- AWS Unsubscribe -----------------------------------------------------------
    data = "AT+AWS_UNSUB=".encode() + topic.encode() + '\n'.encode()
    self.sp.write(data)
    time.sleep(0.01)

    data = self.sp.readline()
    if("SUCCEED\n".encode() == data):
      print("OK")
    else:
      print("Fail")
    
    data = self.sp.readline()
    time.sleep(0.01)

    data = self.sp.readline()
    if("EVENT:UNSUB OK\n".encode() == data):
      print("OK")
    else:
      print("Fail")

  #-----------------------------------------------------------------------------
  def delta(self, key, ty):

    #--- AWS Update -----------------------------------------------------------
    data = "AT+AWS_DELTA=".encode() +key.encode() + ','.encode()+ str(ty).encode()  +'\n'.encode()
    self.sp.write(data)
    time.sleep(0.01)

    data = self.sp.readline()
    if("SUCCEED\n".encode() == data):
      print("OK")
    else:
      print("Fail")
    
    data = self.sp.readline()
    time.sleep(0.01)
    
    data = self.sp.readline()
    if("EVENT:DELTA OK\n".encode() == data):
      print("OK")
    else:
      print("Fail")

  #-----------------------------------------------------------------------------
  #-----------------------------------------------------------------------------
  def wait_sub(self):
    while(True):
      data = self.sp.readline()
      time.sleep(0.01)
      print(data)

  #-----------------------------------------------------------------------------
  #-----------------------------------------------------------------------------
  def g3_cmd(self, pkt, dp):

    data = 'AT+G3={}\n'.format(pkt).encode()
    #print(data)
    
    self.sp.write(data)
    time.sleep(0.2)

   # data = self.sp.readline()    


  
    data = self.sp.read(1)
    n = self.sp.inWaiting()
    data = data + self.sp.readline()

    print(dp)
   
  
    if("\n3630\n".encode()== data):
     print("Error : wrong password")
     sys.exit(1)      
  
    time.sleep(1.0)

  #-----------------------------------------------------------------------------
  #-----------------------------------------------------------------------------
  def g3_profile(self, pkt):

    data = 'AT+G3_PROFILE={}\n'.format(pkt).encode()
    #print(data)
    
    self.sp.write(data)
    #time.sleep(0.01

    data = self.sp.readline()
    #print(data)
    time.sleep(1.0)

#===============================================================================
if __name__ == "__main__":


  sp = serial.Serial(port='\\\\.\\COM5', 
                    baudrate=115200,
                    bytesize=serial.EIGHTBITS,
                    parity=serial.PARITY_NONE,
                    stopbits=serial.STOPBITS_TWO,
                    rtscts=False,
                    dsrdtr=False,
                    xonxoff=False,
                    timeout=None)

  time.sleep(1.0)
