#!/usr/bin/env python3
"""Build and verify first-flash artifacts. Never invokes a probe or writes a device."""
import argparse,hashlib,json,pathlib,shutil,subprocess,sys,os
ROOT=pathlib.Path(__file__).resolve().parents[1]
def run(*args,cwd=ROOT,**kw):return subprocess.run(args,cwd=cwd,check=True,**kw)
def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--features',default='',help='extra board cargo features, comma separated')
 features=[f for f in parser.parse_args().features.split(',') if f]
 run(sys.executable,'scripts/check.py','--checkpoint');run('cargo','clippy','--all-targets','--','-D','warnings')
 board=ROOT/'board/nrf52840';extra=['--features',','.join(features)] if features else []
 run('cargo','build','--release','--locked',*extra,cwd=board)
 elf=board/'target/thumbv7em-none-eabihf/release/microcard-nrf52840';out=ROOT/'artifacts/first-flash';out.mkdir(parents=True,exist_ok=True)
 shutil.copy2(elf,out/'microcard.elf');run('arm-none-eabi-objcopy','-O','ihex',str(elf),str(out/'microcard.hex'))
 # Inspect load addresses rather than trusting the link succeeding.
 headers=run('arm-none-eabi-objdump','-h',str(elf),capture_output=True,text=True).stdout.splitlines()
 for i,line in enumerate(headers):
  fields=line.split()
  if len(fields)>=7 and fields[0].isdigit() and i+1<len(headers) and 'LOAD' in headers[i+1]:
   length=int(fields[2],16);address=int(fields[4],16)
   if length and address+length>0xB0000:raise RuntimeError('load section overlaps reserved flash')
 binary=out/'microcard.bin';run('arm-none-eabi-objcopy','-O','binary',str(elf),str(binary));raw=binary.read_bytes()
 sp=int.from_bytes(raw[:4],'little');reset=int.from_bytes(raw[4:8],'little')
 if sp!=0x20040000 or reset&1!=1 or not 0<reset<0xB0000:raise RuntimeError('invalid initial stack/reset vector')
 sizes=run('arm-none-eabi-size' ,str(elf),capture_output=True,text=True).stdout.splitlines()[1].split();text,data,bss=map(int,sizes[:3])
 if bss+data>208896:raise RuntimeError('less than 52 KiB stack margin')
 for stem in ['counter','keys']:
  for ext in ['mca','json','map.json']:shutil.copy2(ROOT/f'work/{stem}.{ext}',out/f'{stem}.{ext}')
 result={'git_revision':run('git','rev-parse','HEAD',capture_output=True,text=True).stdout.strip(),'working_tree_dirty':bool(run('git','status','--porcelain',capture_output=True,text=True).stdout),'flash_text':text,'ram_bss':bss,'ram_data':data,'checks':'host corpus, text and binary SCP03/key scenarios, clippy, release cross-build, flash sections','hardware_flashed':False,'board_features':features,'sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir() if p.is_file() and p.name!='manifest.json'}}
 (out/'manifest.json').write_text(json.dumps(result,indent=2)+'\n');print('Prepared',out,'without accessing a device')
if __name__=='__main__':main()
