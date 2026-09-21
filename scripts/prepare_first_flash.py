#!/usr/bin/env python3
"""Build and verify first-flash artifacts. Never invokes a probe or writes a device."""
import argparse,hashlib,json,pathlib,shutil,struct,subprocess,sys,os,tempfile
from firmware_link import inspect_link
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
def publish_bundle(staged, destination):
 """Replace a complete generated bundle; restore the previous one if publication fails."""
 destination.parent.mkdir(parents=True,exist_ok=True)
 backup=pathlib.Path(tempfile.mkdtemp(prefix='.previous-',dir=destination.parent))
 previous=backup/'bundle'
 try:
  if destination.exists():destination.rename(previous)
  try:staged.rename(destination)
  except BaseException:
   # If restoration itself fails, keep the backup on disk for manual recovery.
   if previous.exists():previous.rename(destination)
   raise
 except BaseException:
  if not previous.exists():backup.rmdir()
  raise
 else:shutil.rmtree(backup)

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--engine',choices=('mc04','jcvm'),required=True)
 parser.add_argument('--features',default='',help='extra board cargo features, comma separated')
 parser.add_argument('--development-only',action='store_true',
                     help='build a flashable hardware-iteration bundle without the checkpoint gate')
 args=parser.parse_args()
 features=[f'engine-{args.engine}',*[f for f in args.features.split(',') if f]]
 if f"engine-{'jcvm' if args.engine=='mc04' else 'mc04'}" in features:parser.error('features select a different engine')
 if not args.development_only:
  run(sys.executable,'scripts/check.py','--checkpoint');run('cargo','clippy','--all-targets','--','-D','warnings')
 board=ROOT/'board/nrf52840';extra=['--features',','.join(features)] if features else []
 # The flash window comes from the linker map the build will use, so this script and the
 # image agree about where the application ends on either board.
 dongle='dongle' in features or 'dongle-layout' in features
 layout=board/f"memory-{'dongle' if dongle else 'dk'}{'-jcvm' if args.engine=='jcvm' else ''}.x"
 flash_origin,flash_length=flash_region(layout);flash_end=flash_origin+flash_length
 target=board/'target/profiles'/f'first-flash-{args.engine}-{"dongle" if dongle else "dk"}'
 link_map=target/f'microcard-{args.engine}.map'
 run('cargo','rustc','--release','--locked','--target-dir',str(target),*extra,
     '--','-C',f'link-arg=-Map={link_map}',cwd=board)
 elf=target/'thumbv7em-none-eabihf/release/microcard-nrf52840'
 link=inspect_link(elf,link_map,hardware=True)
 artifact_kind='development-firmware' if args.development_only else 'first-flash'
 destination=ROOT/'artifacts'/artifact_kind/args.engine/('dongle' if dongle else 'dk')
 destination.parent.mkdir(parents=True,exist_ok=True)
 staging=tempfile.TemporaryDirectory(prefix='.preparing-',dir=destination.parent)
 out=pathlib.Path(staging.name)/'bundle';out.mkdir()
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
 for stem in (['counter','keys'] if args.engine=='mc04' else []):
  for ext in ['mca','json','map.json']:shutil.copy2(ROOT/f'work/{stem}.{ext}',out/f'{stem}.{ext}')
 checks=['release cross-build','flash sections','initial stack/reset vector',
         'static stack margin','hardware-provider link inspection']
 if not args.development_only:checks[:0]=['host checkpoint','workspace clippy']
 result={'engine':args.engine,'layout':layout.name,'layout_sha256':hashlib.sha256(layout.read_bytes()).hexdigest(),'git_revision':run('git','rev-parse','HEAD',capture_output=True,text=True).stdout.strip(),'working_tree_dirty':bool(run('git','status','--porcelain',capture_output=True,text=True).stdout),'development_only':args.development_only,'flash_text':text,'ram_bss':bss,'ram_data':data,'checks':checks,'link_inspection':link,'hardware_flashed':False,'board_features':features,'flash_origin':flash_origin,'flash_end':flash_end,'sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir() if p.is_file() and p.name!='manifest.json'}}
 (out/'manifest.json').write_text(json.dumps(result,indent=2)+'\n')
 publish_bundle(out,destination)
 staging.cleanup()
 print('Prepared',destination,'without accessing a device')
if __name__=='__main__':main()
