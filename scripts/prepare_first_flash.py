#!/usr/bin/env python3
"""Build and verify first-flash artifacts. Never invokes a probe or writes a device."""
import argparse,hashlib,json,pathlib,shutil,struct,subprocess,sys,os
ROOT=pathlib.Path(__file__).resolve().parents[1]
def run(*args,cwd=ROOT,**kw):return subprocess.run(args,cwd=cwd,check=True,**kw)
def flash_region(path):
 """Read ORIGIN and LENGTH of the FLASH region from a linker memory map."""
 for line in path.read_text().splitlines():
  name,_,rest=line.strip().partition(':')
  if name.strip()!='FLASH':continue
  def field(key):
   value=rest.split(key,1)[1].lstrip().lstrip('=').strip().split(',')[0].strip()
   return int(value,16) if value.lower().startswith('0x') else int(value.rstrip('K'))*1024
  return field('ORIGIN'),field('LENGTH')
 raise RuntimeError(f'no FLASH region in {path}')
MAKERDIARY_MDK_DONGLE_FAMILY=0x2886F00F
def write_uf2(raw,origin,destination):
 """Wrap a raw image as UF2, which is how a bootloader-equipped dongle is flashed.

 Blocks are 512 bytes carrying 256 payload bytes each. The family identifier is the one
 this board's own bootloader announces in its CURRENT.UF2, which is its USB vendor and
 product pair rather than the generic nRF52840 family. A bootloader ignores every block
 whose family it does not recognize, so the wrong value here writes nothing at all.
 """
 payload=256;blocks=(len(raw)+payload-1)//payload;image=bytearray()
 for index in range(blocks):
  chunk=raw[index*payload:(index+1)*payload];chunk=chunk+bytes(payload-len(chunk))
  image+=struct.pack('<8I',0x0A324655,0x9E5D5157,0x00002000,origin+index*payload,payload,index,blocks,MAKERDIARY_MDK_DONGLE_FAMILY)
  image+=chunk+bytes(476-payload)+struct.pack('<I',0x0AB16F30)
 destination.write_bytes(bytes(image))
def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--features',default='',help='extra board cargo features, comma separated')
 features=[f for f in parser.parse_args().features.split(',') if f]
 run(sys.executable,'scripts/check.py','--checkpoint');run('cargo','clippy','--all-targets','--','-D','warnings')
 board=ROOT/'board/nrf52840';extra=['--features',','.join(features)] if features else []
 # The flash window comes from the linker map the build will use, so this script and the
 # image agree about where the application ends on either board.
 dongle='dongle' in features or 'dongle-layout' in features
 layout=board/('memory-dongle.x' if dongle else 'memory-dk.x')
 flash_origin,flash_length=flash_region(layout);flash_end=flash_origin+flash_length
 run('cargo','build','--release','--locked',*extra,cwd=board)
 elf=board/'target/thumbv7em-none-eabihf/release/microcard-nrf52840';out=ROOT/'artifacts/first-flash';out.mkdir(parents=True,exist_ok=True)
 shutil.copy2(elf,out/'microcard.elf');run('arm-none-eabi-objcopy','-O','ihex',str(elf),str(out/'microcard.hex'))
 # Inspect load addresses rather than trusting the link succeeding.
 headers=run('arm-none-eabi-objdump','-h',str(elf),capture_output=True,text=True).stdout.splitlines()
 for i,line in enumerate(headers):
  fields=line.split()
  if len(fields)>=7 and fields[0].isdigit() and i+1<len(headers) and 'LOAD' in headers[i+1]:
   length=int(fields[2],16);address=int(fields[4],16)
   if length and not (flash_origin<=address and address+length<=flash_end):raise RuntimeError('load section overlaps reserved flash')
 binary=out/'microcard.bin';run('arm-none-eabi-objcopy','-O','binary',str(elf),str(binary));raw=binary.read_bytes()
 sp=int.from_bytes(raw[:4],'little');reset=int.from_bytes(raw[4:8],'little')
 if sp!=0x20040000 or reset&1!=1 or not flash_origin<reset<flash_end:raise RuntimeError('invalid initial stack/reset vector')
 # A dongle has no debug probe, so its image ships as UF2 for the bootloader's drag and drop.
 if dongle:write_uf2(raw,flash_origin,out/'microcard.uf2')
 sizes=run('arm-none-eabi-size' ,str(elf),capture_output=True,text=True).stdout.splitlines()[1].split();text,data,bss=map(int,sizes[:3])
 if bss+data>208896:raise RuntimeError('less than 52 KiB stack margin')
 for stem in ['counter','keys']:
  for ext in ['mca','json','map.json']:shutil.copy2(ROOT/f'work/{stem}.{ext}',out/f'{stem}.{ext}')
 result={'git_revision':run('git','rev-parse','HEAD',capture_output=True,text=True).stdout.strip(),'working_tree_dirty':bool(run('git','status','--porcelain',capture_output=True,text=True).stdout),'flash_text':text,'ram_bss':bss,'ram_data':data,'checks':'host corpus, text and binary SCP03/key scenarios, clippy, release cross-build, flash sections','hardware_flashed':False,'board_features':features,'flash_origin':flash_origin,'flash_end':flash_end,'sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir() if p.is_file() and p.name!='manifest.json'}}
 (out/'manifest.json').write_text(json.dumps(result,indent=2)+'\n');print('Prepared',out,'without accessing a device')
if __name__=='__main__':main()
