#!/usr/bin/env python3
"""Post-flash UART smoke test. Does not flash, erase, recover or reset a device."""
import argparse,os,pathlib,select,termios,time,subprocess,tempfile
from scp03_acceptance import Client,ROOT,SIM,bootstrap_isd
class SerialClient(Client):
 def __init__(self,keys,port):
  self.keys=pathlib.Path(keys).read_bytes()
  if len(self.keys)!=32:raise ValueError('management key file must contain 32 bytes')
  self.fd=os.open(port,os.O_RDWR|os.O_NOCTTY|os.O_NONBLOCK)
  a=termios.tcgetattr(self.fd);a[0]=0;a[1]=0;a[2]=termios.CS8|termios.CREAD|termios.CLOCAL;a[3]=0;a[4]=termios.B115200;a[5]=termios.B115200;a[6][termios.VMIN]=0;a[6][termios.VTIME]=0
  termios.tcsetattr(self.fd,termios.TCSANOW,a);termios.tcflush(self.fd,termios.TCIOFLUSH)
 def raw(self,b):
  packet=len(b).to_bytes(2,'little')+b;deadline=time.monotonic()+10
  while packet:
   if not select.select([],[self.fd],[],max(0,deadline-time.monotonic()))[1]:raise TimeoutError('UART send')
   packet=packet[os.write(self.fd,packet):]
  def read(n):
   result=b''
   while len(result)<n:
    if not select.select([self.fd],[],[],max(0,deadline-time.monotonic()))[0]:raise TimeoutError('UART response')
    chunk=os.read(self.fd,n-len(result))
    if not chunk:raise EOFError('UART closed')
    result+=chunk
   return result
  n=int.from_bytes(read(2),'little')
  if not 2<=n<=258:raise ValueError('invalid response frame length')
  return read(n)
 def close(self):os.close(self.fd)
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--port',required=True);parser.add_argument('--management-key',required=True);parser.add_argument('--signing-seed',required=True);parser.add_argument('--domain',required=True,help='new SSD identifier; an existing domain is never deleted');a=parser.parse_args()
 c=SerialClient(a.management_key,a.port)
 try:
  c.connect()
  # A freshly flashed card has no ISD owner, so SSD creation would fail closed.
  bootstrap_isd(c,pathlib.Path(a.signing_seed).read_bytes())
  inc=c.command(0xe0,a.domain.encode())
  with tempfile.TemporaryDirectory(prefix='microcard-dk-') as td:
   package=pathlib.Path(td)/'keys.mcp'
   subprocess.run([SIM,'pack',ROOT/'work/keys.mca',ROOT/'work/keys.json',a.domain,inc.hex(),'1',a.signing_seed,package,'--explicit-sign'],check=True)
   raw=package.read_bytes();c.command(0xe6)
   for offset in range(0,len(raw),200):c.command(0xe8,offset.to_bytes(4,'little')+raw[offset:offset+200])
   c.command(0xea)
   import json
   for aid in ['F04D430010','F04D430011','F04D430012']:c.command(0xec,json.dumps([a.domain,aid],separators=(',',':')).encode())
   c.command(0xa4,bytes.fromhex('F04D430010'));tag=c.command(0x10,b'\x00');assert len(tag)==32
   assert len(c.command(0x10,b'\x01'))==16
   assert c.command(0x10,b'\x02')==b'a';assert c.command(0x10,b'\x03')==b'a'
   c.command(0xa4,bytes.fromhex('F04D430011'));assert c.command(0x10)==tag
   c.command(0xa4,bytes.fromhex('F04D430012'));assert c.command(0x10,b'\x02')==b'\x00';c.command(0x10,b'\x00');assert c.command(0x10,b'\x01')==b'blo'
   print('PASS: UART SCP03, signed loading, installation, persistent key operations and shared domain state')
 finally:c.close()
if __name__=='__main__':main()
