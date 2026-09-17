#!/usr/bin/env python3
"""Exercise the real UART client through a POSIX pseudo-terminal and binary simulator."""
import os,pathlib,pty,subprocess,tempfile,threading
from dk_smoke import SerialClient,SIM
from scp03_acceptance import bootstrap_isd

def main():
 with tempfile.TemporaryDirectory(prefix='microcard-uart-') as td:
  td=pathlib.Path(td);key=td/'management.key';key.write_bytes(os.urandom(32));key.chmod(0o600)
  master,slave=pty.openpty();client=SerialClient(key,os.ttyname(slave))
  p=subprocess.Popen([SIM,'serve-binary',key,td/'state'],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
  def input_loop():
   try:
    while True:
     b=os.read(master,1024)
     if not b:return
     p.stdin.write(b);p.stdin.flush()
   except (OSError,ValueError):pass
  def output_loop():
   try:
    while True:
     b=os.read(p.stdout.fileno(),3)
     if not b:return
     while b:b=b[os.write(master,b):]
   except (OSError,ValueError):pass
  threads=[threading.Thread(target=f,daemon=True) for f in [input_loop,output_loop]]
  for t in threads:t.start()
  try:
   client.connect();bootstrap_isd(client);assert len(client.command(0xe0,b'uart'))==16
   client.command(0xff,bytes(223),status=0x6985)
   client.command(0xe4,b'uart')
  finally:
   client.close();p.terminate();p.wait(timeout=5);os.close(slave);os.close(master)
 print('PASS: real serial adapter over fragmented pseudo-terminal SCP03 frames')
if __name__=='__main__':main()
