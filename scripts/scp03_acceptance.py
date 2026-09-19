#!/usr/bin/env python3
"""Independent host-side SCP03 implementation, GP 1.1.2 §§4.1.5, 6.2.
Uses Python cryptography/OpenSSL, not the Rust implementation. Development acceptance only.
"""
from device_cbor import management_names, manifest as encode_manifest
from package_envelope import create as create_envelope, PREFIX as PACKAGE_PREFIX
import hashlib, json, os, pathlib, subprocess, tempfile
from validation_common import prebuilt, require_artifacts
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
ROOT=pathlib.Path(__file__).resolve().parents[1]
SIM=ROOT/'target/debug/microcard-sim'
# Extra cargo arguments for the simulator build, so the same oracle can be replayed against
# a card built with a different set of SCP03 capabilities.
BUILD=os.environ.get('MICROCARD_BUILD','').split()
def cmac(k,b):
 c=CMAC(algorithms.AES(k)); c.update(b); return c.finalize()
def kdf(k,c,bits,context): return cmac(k,bytes(11)+bytes([c,0])+bits.to_bytes(2,'big')+b'\x01'+context)
def aes(k,mode,data):
 e=Cipher(algorithms.AES(k),mode).encryptor(); return e.update(data)+e.finalize()
def unaes(k,mode,data):
 d=Cipher(algorithms.AES(k),mode).decryptor(); return d.update(data)+d.finalize()
class Client:
 def __init__(self,keys,state,mode='serve'):
  self.keys=keys.read_bytes();self.p=subprocess.Popen([SIM,mode,keys,state],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
 def raw(self,b):
  self.p.stdin.write(b.hex()+'\n');self.p.stdin.flush();line=self.p.stdout.readline();assert line,'simulator terminated';return bytes.fromhex(line)
 def connect(self,level=None):
  # Ask with the legacy width first. A card in S16 reports the wrong length, which is
  # how a host discovers the mode without knowing it in advance.
  host=os.urandom(8);probe=self.raw(bytes.fromhex('8050000008')+host+b'\x00')
  self.s16=probe[-2:]==b'\x67\x00'
  self.width=16 if self.s16 else 8
  if self.s16:
   host=os.urandom(16);r=self.raw(bytes.fromhex('8050000010')+host+b'\x00')
  else:
   r=probe
  assert r[-2:]==b'\x90\x00',r.hex()
  kvn,scp,i=r[10],r[11],r[12]
  assert (kvn,scp)==(1,3),'SCP03 key information mismatch'
  assert bool(i&0x01)==self.s16,'announced S16 bit disagrees with the response length'
  # Ten diversification bytes, three of key information, challenge, cryptogram, and the
  # sequence counter only where the challenge is derived from it.
  sequence=3 if i&0x10 else 0
  assert len(r)==10+3+2*self.width+sequence+2,(len(r),r.hex())
  self.i=i
  # Without an explicit request, take every protection the card announces.
  self.supported=0x03|(0x10 if i&0x20 else 0)|(0x20 if i&0x40 else 0)
  if level is None: level=self.supported
  bits=128 if self.s16 else 64
  if sequence:
   # A derived challenge is reproducible from the counter, so recompute it here.
   counter=r[13+2*self.width:13+2*self.width+3]
   assert r[13:13+self.width]==kdf(self.keys[:16],2,bits,counter+bytes.fromhex('A000000151000000'))[:self.width]
   assert counter>getattr(self,'counter_seen',b''),'sequence counter did not advance'
   self.counter_seen=counter
  context=host+r[13:13+self.width];self.enc=kdf(self.keys[:16],4,128,context);self.mac=kdf(self.keys[16:],6,128,context);self.rmac=kdf(self.keys[16:],7,128,context)
  assert r[13+self.width:13+2*self.width]==kdf(self.mac,0,bits,context)[:self.width]
  self.chain=bytes(16);self.counter=0;self.level=level
  cryptogram=kdf(self.mac,1,bits,context)[:self.width]
  b=bytes([0x84,0x82,level,0,2*self.width])+cryptogram;self.chain=cmac(self.mac,self.chain+b)
  assert self.raw(b+self.chain[:self.width])==b'\x90\x00'
 def encode(self,ins,data=b'',p1=0,p2=0,cla=0x84):
  self.counter+=1
  if self.level&2 and data:
   padded=data+b'\x80';padded+=bytes((-len(padded))%16)
   iv=aes(self.enc,modes.ECB(),self.counter.to_bytes(16,'big'));data=aes(self.enc,modes.CBC(iv),padded)
  b=bytes([cla,ins,p1,p2,len(data)+self.width])+data;self.chain=cmac(self.mac,self.chain+b);return b+self.chain[:self.width]
 def command(self,ins,data=b'',status=0x9000,p1=0,p2=0,cla=0x84):
  r=self.raw(self.encode(ins,data,p1,p2,cla));assert r[-2:]==status.to_bytes(2,'big'),(hex(ins),r.hex())
  if self.level&0x10 and (status==0x9000 or status>>8 in (0x62,0x63)): return self.unprotect(r)
  return r[:-2]
 def unprotect(self,r):
  """Verify the response MAC and recover the body, SCP03 §§6.2.6-6.2.7."""
  cut=self.width+2;assert len(r)>=cut
  assert r[-cut:-2]==cmac(self.rmac,self.chain+r[:-cut]+r[-2:])[:self.width]
  body=r[:-cut]
  # The R-MAC covers the ciphered data, so decryption follows verification.
  if self.level&0x20 and body:
   iv=aes(self.enc,modes.ECB(),bytes([0x80])+self.counter.to_bytes(16,'big')[1:])
   plain=unaes(self.enc,modes.CBC(iv),body);body=plain[:plain.rindex(0x80)]
  return body
 def close(self): self.p.stdin.close();assert self.p.wait(timeout=5)==0

class BinaryClient(Client):
 def __init__(self,keys,state,mode='serve'):
  self.keys=keys.read_bytes();self.p=subprocess.Popen([SIM,mode+'-binary',keys,state],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
 def raw(self,b):
  self.p.stdin.write(len(b).to_bytes(2,'little')+b);self.p.stdin.flush()
  def read(n):
   import select
   result=b''
   while len(result)<n:
    if not select.select([self.p.stdout],[],[],10)[0]:raise TimeoutError('binary simulator response')
    chunk=os.read(self.p.stdout.fileno(),n-len(result));assert chunk,'simulator terminated';result+=chunk
   return result
  n=int.from_bytes(read(2),'little');assert 2<=n<=258;return read(n)
if os.environ.get('MICROCARD_BINARY')=='1':Client=BinaryClient

def domain_policy(identifier,capabilities,max_assemblies=4,max_instances=4,max_int_records=512,max_blob_records=64,max_blob_bytes=8192,max_key_slots=8,max_package_bytes=16384):
 name=identifier.encode();bits=sum(1<<capability for capability in capabilities)
 return bytes([1,len(name)])+name+bits.to_bytes(8,'little')+bytes([max_assemblies,max_instances])+max_int_records.to_bytes(2,'little')+bytes([max_blob_records])+max_blob_bytes.to_bytes(2,'little')+bytes([max_key_slots])+max_package_bytes.to_bytes(2,'little')

def ensure_assembly(project, output):
 image=ROOT/'work'/f'{output}.mca'; metadata=ROOT/'work'/f'{output}.json'
 if prebuilt():
  require_artifacts(image, metadata)
  return image, metadata
 inputs=[ROOT/'build/MicroCard.targets']
 for source_root in (ROOT/project,ROOT/'managed/MicroCard.Tool',ROOT/'managed/MicroCard.Framework'):
  inputs.extend(path for path in source_root.rglob('*') if path.suffix in ('.cs','.csproj'))
 if image.exists() and metadata.exists() and max(path.stat().st_mtime_ns for path in inputs)<=min(image.stat().st_mtime_ns,metadata.stat().st_mtime_ns): return image,metadata
 framework=ROOT/'managed/MicroCard.Framework/bin/Release/net10.0/MicroCard.Framework.dll'
 tool=ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'
 for item in ('managed/MicroCard.Framework','managed/MicroCard.Tool',project):
  subprocess.run(['dotnet','build',item,'-c','Release','--nologo','--verbosity','quiet'],cwd=ROOT,check=True)
 pin=hashlib.sha256(framework.read_bytes()).hexdigest()
 assembly_name='MicroCard.Core' if pathlib.Path(project).name=='CoreLib' else pathlib.Path(project).name
 assembly=ROOT/project/'bin/Release/net10.0'/f'{assembly_name}.dll'
 subprocess.run(['dotnet',tool,assembly,ROOT/'work'/output,framework,pin],cwd=ROOT,check=True)
 return image,metadata

# MP05 packages are signed with P-256 ECDSA over SHA-256. The signer key travels as an
# uncompressed SEC1 point and what a domain binds to is that point's digest.
P256_ORDER=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

def signing_key(seed):
 return ec.derive_private_key(int.from_bytes(seed,'big'),ec.SECP256R1())

def signer_public_key(seed):
 return signing_key(seed).public_key().public_bytes(Encoding.X962,PublicFormat.UncompressedPoint)

def signer_identity(seed):
 """The 32-byte identity a domain binds to."""
 return hashlib.sha256(signer_public_key(seed)).digest()

def sign_package(seed,message):
 """Fixed-width r and s, in the low form the card requires."""
 r,s=decode_dss_signature(signing_key(seed).sign(message,ec.ECDSA(hashes.SHA256())))
 if s>P256_ORDER//2: s=P256_ORDER-s
 return r.to_bytes(32,'big')+s.to_bytes(32,'big')

def new_seed():
 """A random 32-byte value that is a usable P-256 scalar."""
 while True:
  candidate=os.urandom(32)
  if 0<int.from_bytes(candidate,'big')<P256_ORDER: return candidate

def package_envelope(meta,image,seed):
 return create_envelope(meta,image,signer_public_key(seed),lambda prefix: sign_package(seed,prefix))


def bootstrap_isd(c, signing_seed=bytes([0x42])*32):
 record=c.command(0xe2,b'\x00');assert record[4:7]==b'ISD'
 incarnation=record[7:23]
 if record[23]: return incarnation
 image_path,metadata_path=ensure_assembly('samples/CoreLib','mscorlib')
 image=image_path.read_bytes(); generated=json.loads(metadata_path.read_text())
 manifest=dict(domain='ISD',incarnation=list(incarnation),assembly=generated['assembly'],assembly_version=generated['assembly_version'],version=1,
               export=generated['export'],entry_points=generated['entry_points'],dependencies=generated['dependencies'],capabilities=generated['capabilities'],storage=generated['storage'],
               limits=dict(arena=16384,stack=256,frames=32,instructions=100000))
 meta=encode_manifest(manifest)
 raw=package_envelope(meta,image,signing_seed)
 c.command(0xe6)
 for offset in range(0,len(raw),200):c.command(0xe8,offset.to_bytes(4,'little')+raw[offset:offset+200])
 c.command(0xea)
 return incarnation

def main():
 if prebuilt():
  if BUILD: raise ValueError('Prebuilt acceptance cannot change simulator features')
  require_artifacts(SIM)
 else:
  subprocess.run(['cargo','build','-q',*BUILD],cwd=ROOT,check=True)
 ensure_assembly('samples/Counter','counter')
 ensure_assembly('samples/KeyOperations','keys')
 with tempfile.TemporaryDirectory(prefix='microcard-') as td:
  td=pathlib.Path(td);keys=td/'management.key';keys.write_bytes(os.urandom(32));keys.chmod(0o600)
  c=Client(keys,td/'state')
  select=bytes.fromhex('00A4040008A000000151000000');fci=c.raw(select)
  assert fci[:4]==bytes.fromhex('6F368408') and bytes.fromhex('A000000151000000') in fci and fci[-2:]==b'\x90\x00'
  # The card recognition data ends the SCP03 OID with the i parameter, so read it here
  # and hold it against what INITIALIZE UPDATE announces.
  oid=bytes.fromhex('2A864886FC6B0403');assert oid in fci;announced=fci[fci.index(oid)+len(oid)]
  card_data=c.raw(bytes.fromhex('80CA006600'));assert card_data[:4]==bytes.fromhex('66267324') and card_data[-2:]==b'\x90\x00'
  assert c.raw(bytes.fromhex('80CA9F7F00'))==b'\x6a\x88'
  c.connect();assert c.i==announced,'card recognition data and INITIALIZE UPDATE disagree on i'
  bootstrap_isd(c)
  isd=c.command(0xf2,b'\x4f\x00',p1=0x80,p2=0x02);assert isd[:4]==b'\xe3\x13\x4f\x08' and bytes.fromhex('A000000151000000') in isd
  inc=c.command(0xe0,b'team');assert len(inc)==16
  subprocess.run([SIM,'keygen',td/'signing.seed'],check=True)
  subprocess.run([SIM,'pack',ROOT/'work/counter.mca',ROOT/'work/counter.json','team',inc.hex(),'1',td/'signing.seed',td/'counter.mcp','--explicit-sign'],check=True)
  package=(td/'counter.mcp').read_bytes();c.command(0xe6)
  capabilities=json.loads((ROOT/'work/counter.json').read_text())['capabilities'];assert len(capabilities)>1
  denied=domain_policy('team',capabilities[:-1]);c.command(0xe1,denied);assert c.command(0xe3,b'team')==denied[:1]+denied[6:]
  for offset in range(0,len(package),200):c.command(0xe8,offset.to_bytes(4,'little')+package[offset:offset+200])
  c.command(0xea,status=0x6985);inventory=c.command(0xe2,b'\x01');assert inventory[4+inventory[3]+16]==0
  allowed=domain_policy('team',capabilities);c.command(0xe1,allowed);assert c.command(0xe3,b'team')==allowed[:1]+allowed[6:];c.command(0xe6)
  for offset in range(0,len(package),200):
   chunk=offset.to_bytes(4,'little')+package[offset:offset+200];c.command(0xe8,chunk);c.command(0xe8,chunk) # idempotent retry
  subprocess.run(['dotnet',ROOT/'managed/MicroCard.Pack/bin/Release/net10.0/MicroCard.Pack.dll',ROOT/'work/counter.mca',ROOT/'work/counter.json','team',inc.hex(),'1',td/'signing.seed',td/'dotnet.mcp','--explicit-sign'],check=True)
  assert (td/'dotnet.mcp').read_bytes()==package,'Rust/.NET signatures differ'
  c.command(0xea);c.command(0xec,management_names("team", "F04D430001"))
  first=c.command(0xf2,b'\x4f\x00',status=0x6310,p1=0x40,p2=0x02);assert first[0]==0xe3 and b'\xc5\x03\x80\x00\x00' in first
  second=c.command(0xf2,b'\x4f\x00',p1=0x40,p2=0x03);assert second[0]==0xe3 and bytes.fromhex('F04D430001') in second
  c.command(0xa4,bytes.fromhex('F04D430001'))
  assert c.command(0x10)==b'\x01';assert c.command(0x10)==b'\x02'
  c.command(0xec,management_names("team", "F04D430002"));c.command(0xa4,bytes.fromhex('F04D430002'));assert c.command(0x10)==(2).to_bytes(4,'little',signed=True)
  c.command(0xec,management_names("team", "F04D430003"));c.command(0xa4,bytes.fromhex('F04D430003'));assert c.command(0x10,b'X')==b'X'
  c.command(0xec,management_names("team", "F04D430004"));c.command(0xa4,bytes.fromhex('F04D430004'));assert c.command(0x10)==hashlib.sha256(b'a').digest()[:1]
  reboot_floor=getattr(c,'counter_seen',b'');c.close()
  c=Client(keys,td/'state');c.connect()
  # A reserved block is durable before it is used, so a restart can only skip values.
  assert getattr(c,'counter_seen',b'')>reboot_floor or not reboot_floor,'sequence counter rolled back'
  c.command(0xa4,bytes.fromhex('F04D430002'));assert c.command(0x10)==(2).to_bytes(4,'little',signed=True)
  c.command(0xa4,bytes.fromhex('F04D430001'));assert c.command(0x10)==b'\x03'
  replay=c.encode(0x10);r=c.raw(replay);assert r[-2:]==b'\x90\x00';assert c.raw(replay)==b'\x69\x82';assert c.raw(c.encode(0x10))==b'\x69\x82'
  # Every level carrying a command MAC serves management, and reading the policy back
  # exercises response integrity and confidentiality wherever the build offers them.
  for level in [l for l in (1,3,0x11,0x13,0x33) if l&~c.supported==0]:
   c.connect(level);assert c.command(0xe3,b'team')==allowed[:1]+allowed[6:],hex(level)
   # The sample reader asks for command confidentiality with integrity both ways. Every
   # level carrying those must serve it, including the ones that protect more.
   c.command(0xa4,bytes.fromhex('F04D430004'))
   expected=0x9000 if level&0x13==0x13 else 0x6982
   assert c.command(0x10,status=expected)==(hashlib.sha256(b'a').digest()[:1] if expected==0x9000 else b''),hex(level)
  # Level 0 carries no MAC, so it authorizes nothing.
  c.connect(0);c.command(0xe0,b'forbidden',0x6985)
  c.connect();bad=bytearray(c.encode(0xe0,b'bad'));bad[-1]^=1;assert c.raw(bad)==b'\x69\x82'
  c.connect();c.command(0xe4,b'team');c.command(0x10,status=0x6982);c.close()
 # A separate state keeps the four-instance quota explicit.
 with tempfile.TemporaryDirectory(prefix='microcard-keys-') as td:
  td=pathlib.Path(td);keys=td/'management.key';keys.write_bytes(os.urandom(32));keys.chmod(0o600)
  c=Client(keys,td/'state');c.connect();bootstrap_isd(c);inc=c.command(0xe0,b'keys')
  subprocess.run([SIM,'keygen',td/'signing.seed'],check=True)
  subprocess.run([SIM,'pack',ROOT/'work/keys.mca',ROOT/'work/keys.json','keys',inc.hex(),'1',td/'signing.seed',td/'keys.mcp','--explicit-sign'],check=True)
  package=(td/'keys.mcp').read_bytes();c.command(0xe6)
  for offset in range(0,len(package),200):c.command(0xe8,offset.to_bytes(4,'little')+package[offset:offset+200])
  c.command(0xea);c.command(0xec,management_names("keys", "F04D430010"));c.command(0xec,management_names("keys", "F04D430011"));c.command(0xec,management_names("keys", "F04D430012"))
  c.command(0xa4,bytes.fromhex('F04D430010'));tag=c.command(0x10,b'\x00');assert len(tag)==32
  aes_tag=c.command(0x10,b'\x01');assert len(aes_tag)==16
  assert c.command(0x10,b'\x02')==b'a';assert c.command(0x10,b'\x03')==b'a'
  # Test oracle reads only this temporary simulator's framework state, never a device or production keys.
  management_keys=keys.read_bytes()
  storage_key=cmac(management_keys[:16],b'MicroCard journal AEAD v1\0'+management_keys[16:])
  snapshots=[]
  for file in (td/'state').glob('slot*.bin'):
   raw=file.read_bytes();generation=int.from_bytes(raw[4:12],'little');n=int.from_bytes(raw[20:24],'little')
   if raw[:4]==b'MJ03' and raw[-1]==0 and 16<=n<=len(raw)-27:
    nonce=b'MCJN3'+raw[12:20]
    try: plaintext=AESCCM(storage_key,tag_length=16).decrypt(nonce,raw[24:24+n],raw[:24])
    except Exception: continue
    from device_cbor import decode
    snapshot=decode(plaintext);assert snapshot[:2]==[2,0]
    snapshots.append((generation,snapshot))
  state=dict(max(snapshots,key=lambda x:x[0])[1][4])['keys'];entries={entry[0]:entry for entry in state[12]}
  import hmac
  assert tag==hmac.digest(entries[0][3],b'a','sha256')
  assert aes_tag==cmac(entries[1][3][:16],b'a')
  assert [entry[0] for entry in state[10]]==[10],'key material leaked into application store'
  c.command(0xa4,bytes.fromhex('F04D430011'));assert c.command(0x10)==tag
  c.command(0xa4,bytes.fromhex('F04D430012'));assert c.command(0x10,b'\x02')==b'\x00';c.command(0x10,b'\x00');assert c.command(0x10,b'\x02')==b'\x01';assert c.command(0x10,b'\x01')==b'blo';c.close()
  c=Client(keys,td/'state');c.connect();c.command(0xa4,bytes.fromhex('F04D430012'));assert c.command(0x10,b'\x01')==b'blo';c.command(0x10,b'\x03');assert c.command(0x10,b'\x02')==b'\x00'
  c.command(0x10,b'\x04',status=0x6982) # failed invocation must roll back its byte-record write
  c.connect();c.command(0xa4,bytes.fromhex('F04D430012'));assert c.command(0x10,b'\x05')==b'\x00'
  c.command(0xa4,bytes.fromhex('F04D430010'));assert c.command(0x10,b'\x00')==tag
  c.command(0x10,b'\x04',status=0x6982) # stale handle faults and rolls back delete/generate
  c.connect();c.command(0xa4,bytes.fromhex('F04D430010'));assert c.command(0x10,b'\x00')==tag
  c.command(0xe4,b'keys');new=c.command(0xe0,b'keys');assert new!=inc;c.close()
 print('PASS: persistent keys and byte records, independent HMAC/CMAC oracle, CBC/CCM, sharing, reboot, transaction rollback and deletion')
 print('PASS: independent SCP03 levels, encrypted signed upload, retry, install, counter, reboot, replay, MAC failure and deletion')
if __name__=='__main__': main()
