use microcard_core::{
    assembly::Assembly,
    domains::Card,
    journal::Flash,
    package::{Manifest, Package},
    scp03::Keys,
    *,
};
use std::{
    env, fs,
    io::{self, BufRead, Read, Seek, SeekFrom, Write},
    path::Path,
};
mod sim_hal;
use sim_hal::Hardware;
const MAX_TEXT_APDU_BYTES: usize = 261;

fn private_open_options() -> fs::OpenOptions {
    let mut options = fs::OpenOptions::new();
    options.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

fn hex(bytes: &[u8]) -> std::result::Result<String, Box<dyn std::error::Error>> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let length = bytes.len().checked_mul(2).ok_or("hex length")?;
    let mut encoded = String::new();
    encoded
        .try_reserve_exact(length)
        .map_err(|_| "hex allocation")?;
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(encoded)
}
fn unhex(s: &str) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !s.len().is_multiple_of(2) {
        return Err("odd hex length".into());
    }
    let length = s.len() / 2;
    if length > MAX_TEXT_APDU_BYTES {
        return Err("hex input exceeds the short-APDU limit".into());
    }
    let mut decoded = Vec::new();
    decoded
        .try_reserve_exact(length)
        .map_err(|_| "hex allocation")?;
    for pair in s.as_bytes().chunks_exact(2) {
        decoded.push(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?);
    }
    Ok(decoded)
}
struct FileFlash {
    dir: std::path::PathBuf,
}
impl FileFlash {
    const MONOTONIC_BYTES: usize = 65536;
    const IO_CHUNK_BYTES: usize = 4096;

    fn path(&self, s: usize) -> std::path::PathBuf {
        self.dir.join(format!("slot{s}.bin"))
    }

    fn monotonic_path(&self) -> std::path::PathBuf {
        self.dir.join("monotonic.bin")
    }

    fn write_erased(file: &mut fs::File, mut remaining: usize) -> Result<()> {
        let erased = [0xff; Self::IO_CHUNK_BYTES];
        while remaining != 0 {
            let length = remaining.min(erased.len());
            file.write_all(&erased[..length])
                .map_err(|_| Error::Storage)?;
            remaining -= length;
        }
        Ok(())
    }

    fn initialize(&mut self) -> Result<()> {
        let slot0 = self.path(0).exists();
        let slot1 = self.path(1).exists();
        let monotonic = self.monotonic_path().exists();
        let nonces = self.dir.join("nonces.bin").exists();
        if !slot0 && !slot1 && !monotonic && !nonces {
            if (0..64).any(|index| self.dir.join(format!("image{index}.bin")).exists()) {
                return Err(Error::IncompatibleState);
            }
            self.erase(0)?;
            self.erase(1)?;
            let mut file = private_open_options()
                .create_new(true)
                .open(self.monotonic_path())
                .map_err(|_| Error::Storage)?;
            Self::write_erased(&mut file, Self::MONOTONIC_BYTES)?;
            file.sync_all().map_err(|_| Error::Storage)?;
            Self::erase_file(&self.dir.join("nonces.bin"), Self::MONOTONIC_BYTES)?;
            return Ok(());
        }
        if slot0 && slot1 && monotonic && !nonces { return Err(Error::IncompatibleState); }
        if slot0 && slot1 && monotonic && nonces {
            return Ok(());
        }
        Err(Error::Storage)
    }
}
impl FileFlash {
    fn erase_file(path: &Path, size: usize) -> Result<()> {
        let mut f = private_open_options()
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|_| Error::Storage)?;
        Self::write_erased(&mut f, size)?;
        f.sync_all().map_err(|_| Error::Storage)?;
        #[cfg(unix)]
        fs::File::open(path.parent().ok_or(Error::Storage)?)
            .and_then(|directory| directory.sync_all()).map_err(|_| Error::Storage)?;
        Ok(())
    }
    fn program_file(path: &Path, size: usize, o: usize, b: &[u8]) -> Result<()> {
        let end = o.checked_add(b.len()).ok_or(Error::Bounds)?;
        if end > size {
            return Err(Error::Bounds);
        }
        let mut f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|_| Error::Storage)?;
        if f.metadata().map_err(|_| Error::Storage)?.len() != size as u64 {
            return Err(Error::Storage);
        }
        f.seek(SeekFrom::Start(o as u64))
            .map_err(|_| Error::Storage)?;
        let mut old = [0; Self::IO_CHUNK_BYTES];
        for chunk in b.chunks(old.len()) {
            f.read_exact(&mut old[..chunk.len()])
                .map_err(|_| Error::Storage)?;
            if old[..chunk.len()]
                .iter()
                .zip(chunk)
                .any(|(previous, next)| previous & next != *next)
            {
                return Err(Error::Storage);
            }
        }
        f.seek(SeekFrom::Start(o as u64))
            .map_err(|_| Error::Storage)?;
        f.write_all(b).map_err(|_| Error::Storage)?;
        f.sync_all().map_err(|_| Error::Storage)
    }
    fn image_path(&self, index: usize) -> Result<std::path::PathBuf> {
        if index >= 64 { return Err(Error::Bounds); }
        Ok(self.dir.join(format!("image{index}.bin")))
    }
}
impl microcard_core::image_store::ImageFlash for FileFlash {
    fn slot_count(&self) -> usize { 64 }
    fn slot_size(&self) -> usize { microcard_core::staging::MAX_PACKAGE_BYTES }
    fn with_slot<T>(&self, index: usize, read: impl FnOnce(&[u8]) -> Result<T>) -> Result<T> {
        let mut file = fs::File::open(self.image_path(index)?).map_err(|_| Error::Storage)?;
        if file.metadata().map_err(|_| Error::Storage)?.len() != microcard_core::staging::MAX_PACKAGE_BYTES as u64 { return Err(Error::Storage); }
        let mut bytes = vec![0; microcard_core::staging::MAX_PACKAGE_BYTES];
        file.read_exact(&mut bytes).map_err(|_| Error::Storage)?;
        read(&bytes)
    }
    fn erase(&mut self, index: usize) -> Result<()> { Self::erase_file(&self.image_path(index)?, microcard_core::staging::MAX_PACKAGE_BYTES) }
    fn program(&mut self, index: usize, offset: usize, bytes: &[u8]) -> Result<()> {
        Self::program_file(&self.image_path(index)?, microcard_core::staging::MAX_PACKAGE_BYTES, offset, bytes)
    }
}
impl FileFlash {
    fn read_counter_file(path: &Path) -> Result<u64> {
        let mut file = fs::File::open(path).map_err(|_| Error::Storage)?;
        if file.metadata().map_err(|_| Error::Storage)?.len() != Self::MONOTONIC_BYTES as u64 {
            return Err(Error::Storage);
        }
        let mut generation = 0u64;
        let mut saw_erased = false;
        let mut buffer = [0; 4096];
        for _ in 0..Self::MONOTONIC_BYTES / buffer.len() {
            file.read_exact(&mut buffer).map_err(|_| Error::Storage)?;
            for word in buffer.chunks_exact(4) {
                let consumed = word.iter().any(|byte| *byte != 0xff);
                if consumed {
                    if saw_erased {
                        return Err(Error::Storage);
                    }
                    generation = generation.checked_add(1).ok_or(Error::Storage)?;
                } else {
                    saw_erased = true;
                }
            }
        }
        Ok(generation)
    }
    fn advance_counter_file(path: &Path, generation: u64) -> Result<()> {
        let index = generation.checked_sub(1).ok_or(Error::Storage)?;
        let offset = usize::try_from(index)
            .map_err(|_| Error::Storage)?
            .checked_mul(4)
            .ok_or(Error::Storage)?;
        if offset + 4 > Self::MONOTONIC_BYTES {
            return Err(Error::Quota);
        }
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|_| Error::Storage)?;
        file.seek(SeekFrom::Start(offset as u64))
            .map_err(|_| Error::Storage)?;
        let mut old = [0; 4];
        file.read_exact(&mut old).map_err(|_| Error::Storage)?;
        if old != [0xff; 4] {
            return Err(Error::Storage);
        }
        file.seek(SeekFrom::Start(offset as u64))
            .map_err(|_| Error::Storage)?;
        file.write_all(&[0; 4]).map_err(|_| Error::Storage)?;
        file.sync_all().map_err(|_| Error::Storage)
    }
}
impl Flash for FileFlash {
    fn slot_size(&self) -> usize {
        65536
    }
    fn monotonic_capacity(&self) -> u64 {
        (Self::MONOTONIC_BYTES / 4) as u64
    }
    fn monotonic_generation(&self) -> Result<u64> { Self::read_counter_file(&self.monotonic_path()) }
    fn advance_monotonic(&mut self, generation: u64) -> Result<()> { Self::advance_counter_file(&self.monotonic_path(), generation) }
    fn nonce_generation(&self) -> Result<u64> { Self::read_counter_file(&self.dir.join("nonces.bin")) }
    fn reserve_nonce(&mut self) -> Result<u64> {
        let next = self.nonce_generation()?.checked_add(1).ok_or(Error::Quota)?;
        Self::advance_counter_file(&self.dir.join("nonces.bin"), next)?;
        Ok(next)
    }
    fn is_erased(&self, s: usize) -> Result<bool> {
        let mut file = fs::File::open(self.path(s)).map_err(|_| Error::Storage)?;
        if file.metadata().map_err(|_| Error::Storage)?.len() != self.slot_size() as u64 {
            return Err(Error::Storage);
        }
        let mut remaining = self.slot_size();
        let mut buffer = [0; Self::IO_CHUNK_BYTES];
        while remaining != 0 {
            let length = remaining.min(buffer.len());
            file.read_exact(&mut buffer[..length])
                .map_err(|_| Error::Storage)?;
            if buffer[..length].iter().any(|byte| *byte != 0xff) {
                return Ok(false);
            }
            remaining -= length;
        }
        Ok(true)
    }
    fn read(&self, s: usize, o: usize, output: &mut [u8]) -> Result<()> {
        let end = o.checked_add(output.len()).ok_or(Error::Bounds)?;
        if end > self.slot_size() {
            return Err(Error::Bounds);
        }
        let mut file = fs::File::open(self.path(s)).map_err(|_| Error::Storage)?;
        if file.metadata().map_err(|_| Error::Storage)?.len() != self.slot_size() as u64 {
            return Err(Error::Storage);
        }
        file.seek(SeekFrom::Start(o as u64))
            .map_err(|_| Error::Storage)?;
        file.read_exact(output).map_err(|_| Error::Storage)
    }
    fn erase(&mut self, s: usize) -> Result<()> { Self::erase_file(&self.path(s), self.slot_size()) }
    fn program(&mut self, s: usize, o: usize, b: &[u8]) -> Result<()> { Self::program_file(&self.path(s), self.slot_size(), o, b) }

}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("microcard-sim {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1)
    }
}
fn run() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let a: Vec<_> = env::args().collect();
    match a.get(1).map(String::as_str){
 Some("keygen") if a.len()==3=>{
  // A P-256 scalar has to lie below the group order, which random bytes do not always do,
  // so draw again rather than writing a seed that cannot sign.
  let mut b=[0;32];
  loop{getrandom::getrandom(&mut b).map_err(|_|"entropy")?;if microcard_core::crypto::p256_private_key_valid(&b){break}}
  let mut f=private_open_options().create_new(true).open(&a[2])?;f.write_all(&b)?;},
 Some("pack") if a.len()==10=>{let mut value:serde_json::Value=serde_json::from_slice(&fs::read(&a[3])?)?;value["domain"]=a[4].clone().into();value["incarnation"]=serde_json::to_value(unhex(&a[5])?)?;value["version"]=a[6].parse::<u32>()?.into();value["limits"]=serde_json::json!({"arena":16384,"stack":256,"frames":32,"instructions":100000});let m:Manifest=serde_json::from_value(value)?;let meta=m.encode_cbor().map_err(|e|format!("{e:?}"))?;let image=fs::read(&a[2])?;let seed: [u8;32]=fs::read(&a[7])?.try_into().map_err(|_|"seed must be 32 bytes")?;if !microcard_core::crypto::p256_private_key_valid(&seed){return Err("seed is not a P-256 private scalar".into())}let public=microcard_core::crypto::p256_public_key(&seed).map_err(|e|format!("{e:?}"))?;let mut b=microcard_core::package::envelope::signing_prefix(&meta,image.len(),&microcard_core::crypto::sha256(&image),&public).map_err(|e|format!("{e:?}"))?;let signature=microcard_core::crypto::p256_ecdsa_sign_package(&seed,&b).map_err(|e|format!("{e:?}"))?;b.extend(signature);b.extend(image);Package::verify(&b).map_err(|e|format!("{e:?}"))?;if a[9]!="--explicit-sign"{return Err("signing requires --explicit-sign".into())}fs::write(&a[8],b)?;},
 Some("verify") if a.len()==3=>{let p=Package::verify(&fs::read(&a[2])?).map_err(|e|format!("{e:?}"))?;println!("{} v{} {}",p.manifest.assembly,p.manifest.version,hex(&p.key)?);},
 Some("verify-assembly") if a.len()==3=>{let bytes=fs::read(&a[2])?;let assembly=Assembly::parse(&bytes).map_err(|e|format!("{e:?}"))?;assembly.framework_imports().map_err(|e|format!("{e:?}"))?;let identity=assembly.identity().map_err(|e|format!("{e:?}"))?;println!("MC04 {} {}.{}.{}.{} {} methods",identity.name,identity.version[0],identity.version[1],identity.version[2],identity.version[3],assembly.row_count(6).map_err(|e|format!("{e:?}"))?);},
 Some("run-mc04") if a.len()>=4=>{let bytes=fs::read(&a[2])?;let assembly=Assembly::parse(&bytes).map_err(|e|format!("{e:?}"))?;let args=a[4..].iter().map(|s|s.parse()).collect::<std::result::Result<Vec<i32>,_>>()?;println!("{:?}",mc04_vm::execute(&assembly,a[3].parse()?,&args).map_err(|e|format!("{e:?}"))?);},
 Some("serve"|"serve-binary") if a.len()==4=>{let b=fs::read(&a[2])?;if b.len()!=32{return Err("management key file must contain ENC16 || MAC16".into())}let keys=Keys{enc:b[..16].try_into()?,mac:b[16..].try_into()?};let mut hardware=Hardware;let storage_key=keys.storage_key_with(&mut hardware).map_err(|e|format!("{e:?}"))?;let dir=Path::new(&a[3]);fs::create_dir_all(dir)?;let mut flash=FileFlash{dir:dir.into()};flash.initialize().map_err(|e|format!("{e:?}"))?;let card=Card::open(flash,hardware,storage_key).map_err(|e|format!("{e:?}"))?;let mut endpoint=microcard_core::transport::Endpoint::new(card,keys);if a[1]=="serve-binary"{use std::io::Read;let mut decoder=microcard_core::framing::Decoder::default();for byte in io::stdin().lock().bytes(){if let Some(frame)=decoder.push(byte?,0){let response=endpoint.exchange(frame);io::stdout().write_all(&(response.len() as u16).to_le_bytes())?;io::stdout().write_all(&response)?;io::stdout().flush()?;}}return Ok(())}for line in io::stdin().lock().lines(){let line=line?;let raw=unhex(line.trim())?;println!("{}",hex(&endpoint.exchange(&raw))?);io::stdout().flush()?;}},
 Some("serve-jcvm") if a.len()==3=>{
  // A Java Card applet, installed and then handed one APDU per line. The transport is
  // the same text protocol the other serve modes use, so a host driving this needs to
  // know nothing about the engine behind it.
  let block=fs::read(&a[2])?;
  let file=microcard_engine_jcvm::cap::LoadFile::parse(&block).map_err(|e|format!("{e:?}"))?;
  let sizes=microcard_engine_jcvm::applet::Sizes{heap_bytes:64*1024,frame_words:8192,..Default::default()};
  let mut card=microcard_engine_jcvm::applet::Card::new(&file,sizes).map_err(|e|format!("{e:?}"))?;
  let mut hardware=Hardware;
  let mut host=microcard_core::jcvm_services::Services(&mut hardware);
  // The install parameters GlobalPlatform would deliver, empty here because nothing has
  // asked for an instance AID or privileges.
  card.install(&file,&mut host,&[0,0,0]).map_err(|e|format!("{e:?}"))?;
  let mut selected=false;
  for line in io::stdin().lock().lines(){
   let line=line?;let raw=unhex(line.trim())?;
   // A SELECT by name is what makes an applet current, JCRE §4.
   let selecting=raw.len()>=4&&raw[0]&0xfc==0&&raw[1]==0xa4&&raw[2]==0x04;
   let answer=card.process(&file,&mut host,&raw,selecting);
   let (data,sw)=match answer{
    Ok(response)=>{if selecting&&response.sw==0x9000{selected=true}(response.data,response.sw)}
    // A failure the engine could not run at all is reported as the status word that says
    // the card does not know what happened, which is what a real card would send.
    Err(_)=>(Vec::new(),0x6f00u16)};
   let _=selected;
   let mut out=data;out.extend(sw.to_be_bytes());
   println!("{}",hex(&out)?);io::stdout().flush()?;
  }
 },
 _=>return Err("commands: keygen PATH | pack ASSEMBLY METADATA DOMAIN INCARNATION_HEX VERSION SEED OUTPUT --explicit-sign | verify PACKAGE | verify-assembly ASSEMBLY | run-mc04 ASSEMBLY METHOD [INT...] | serve MANAGEMENT_KEYS STATE_DIR | serve-jcvm LOAD_FILE".into())}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_apdu_hex_is_bounded_and_canonical() {
        assert_eq!(hex(&[0x00, 0xab, 0xff]).unwrap(), "00ABFF");
        assert_eq!(unhex("00abFF").unwrap(), [0x00, 0xab, 0xff]);
        assert!(unhex("0").is_err());
        assert!(unhex("0G").is_err());
        assert!(unhex(&"AA".repeat(MAX_TEXT_APDU_BYTES)).is_ok());
        assert!(unhex(&"AA".repeat(MAX_TEXT_APDU_BYTES + 1)).is_err());
    }

    #[test]
    fn file_flash_requires_a_complete_monotonic_anchor_set() {
        let directory = std::env::temp_dir().join(format!(
            "microcard-monotonic-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let mut flash = FileFlash {
            dir: directory.clone(),
        };
        flash.initialize().unwrap();
        assert_eq!(flash.monotonic_generation().unwrap(), 0);
        flash.advance_monotonic(1).unwrap();
        assert_eq!(flash.monotonic_generation().unwrap(), 1);
        flash.initialize().unwrap();
        assert_eq!(flash.reserve_nonce().unwrap(), 1);
        assert_eq!(flash.reserve_nonce().unwrap(), 2);
        assert_eq!(flash.monotonic_generation().unwrap(), 1);
        let nonces = flash.dir.join("nonces.bin");
        let saved_nonces = fs::read(&nonces).unwrap();
        fs::remove_file(&nonces).unwrap();
        assert_eq!(flash.initialize(), Err(Error::IncompatibleState));
        assert!(!nonces.exists());
        fs::write(&nonces, saved_nonces).unwrap();

        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(flash.monotonic_path())
            .unwrap();
        file.seek(SeekFrom::Start(8)).unwrap();
        file.write_all(&[0; 4]).unwrap();
        file.sync_all().unwrap();
        assert_eq!(flash.monotonic_generation(), Err(Error::Storage));

        fs::remove_file(flash.monotonic_path()).unwrap();
        assert_eq!(flash.initialize(), Err(Error::Storage));
        fs::remove_file(flash.path(0)).unwrap();
        fs::remove_file(flash.path(1)).unwrap();
        fs::remove_file(nonces).unwrap();
        let image = flash.image_path(0).unwrap();
        fs::write(&image, b"orphaned image").unwrap();
        assert_eq!(flash.initialize(), Err(Error::IncompatibleState));
        assert_eq!(fs::read(image).unwrap(), b"orphaned image");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn file_flash_program_validation_is_atomic_across_chunks() {
        let directory = std::env::temp_dir().join(format!(
            "microcard-flash-atomic-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let mut flash = FileFlash {
            dir: directory.clone(),
        };
        flash.initialize().unwrap();
        assert_eq!(flash.is_erased(0), Ok(true));

        flash.program(0, 4500, &[0]).unwrap();
        let mut before = vec![0; 5000];
        flash.read(0, 0, &mut before).unwrap();
        let mut candidate = vec![0; 5000];
        candidate[4500] = 0xff;
        assert_eq!(flash.program(0, 0, &candidate), Err(Error::Storage));
        let mut after = vec![0; 5000];
        flash.read(0, 0, &mut after).unwrap();
        assert_eq!(after, before);

        fs::remove_dir_all(directory).unwrap();
    }
}
