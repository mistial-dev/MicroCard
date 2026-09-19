use microcard_core::{
    assembly::Assembly,
    domains::Card,
    package::{Manifest, Package},
    scp03::Keys,
    *,
};
use std::{
    env, fs,
    io::{self, BufRead, Write},
    path::Path,
};
mod sim_hal;
mod file_flash;
mod jcvm_storage;
#[cfg(feature = "heap-metrics")]
mod heap_metrics;
use file_flash::FileFlash;
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
fn serve_endpoint<C: microcard_core::engine::CardEngine>(
    mut endpoint: microcard_core::transport::Endpoint<C>, binary: bool,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "heap-metrics")]
    let mut report = heap_metrics::Report::open()?;
    if binary {
        use std::io::Read;
        let mut decoder = microcard_core::framing::Decoder::default();
        for byte in io::stdin().lock().bytes() {
            if let Some(frame) = decoder.push(byte?, 0) {
                #[cfg(feature = "heap-metrics")]
                let response = report.measure("apdu", frame.get(1).copied(), || endpoint.exchange(frame));
                #[cfg(not(feature = "heap-metrics"))]
                let response = endpoint.exchange(frame);
                io::stdout().write_all(&(response.len() as u16).to_le_bytes())?;
                io::stdout().write_all(&response)?;
                io::stdout().flush()?;
            }
        }
    } else {
        for line in io::stdin().lock().lines() {
            let command = unhex(line?.trim())?;
            #[cfg(feature = "heap-metrics")]
            let response = report.measure("apdu", command.get(1).copied(), || endpoint.exchange(&command));
            #[cfg(not(feature = "heap-metrics"))]
            let response = endpoint.exchange(&command);
            println!("{}", hex(&response)?);
            io::stdout().flush()?;
        }
    }
    Ok(())
}

fn lock_state(directory: &Path) -> std::result::Result<fs::File, Box<dyn std::error::Error>> {
    fs::create_dir_all(directory)?;
    let file = private_open_options().read(true).create(true).open(directory.join(".lock"))?;
    file.try_lock().map_err(|_| "state directory is already in use")?;
    Ok(file)
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
 Some("serve"|"serve-binary"|"serve-jcvm-managed"|"serve-jcvm-managed-binary") if a.len()==4=>{
  let bytes=zeroize::Zeroizing::new(fs::read(&a[2])?);
  if bytes.len()!=32 { return Err("management key file must contain ENC16 || MAC16".into()); }
  let keys=Keys { enc:bytes[..16].try_into()?,mac:bytes[16..].try_into()? };
  let directory=Path::new(&a[3]);
  let _state_lock=lock_state(directory)?;
  let binary=a[1].ends_with("-binary");
  if a[1].starts_with("serve-jcvm-managed") {
   #[cfg(feature = "heap-metrics")]
   let opened=heap_metrics::Report::open()?.measure("open",None,||jcvm_storage::open(keys,directory));
   #[cfg(not(feature = "heap-metrics"))]
   let opened=jcvm_storage::open(keys,directory);
   serve_endpoint(opened.map_err(|e|format!("{e:?}"))?,binary)?;
  } else {
   let mut hardware=Hardware;
   let key=keys.storage_key_with(&mut hardware).map_err(|e|format!("{e:?}"))?;
   fs::create_dir_all(directory)?;
   let mut flash=FileFlash { dir:directory.into() };
   flash.initialize().map_err(|e|format!("{e:?}"))?;
   #[cfg(feature = "heap-metrics")]
   let opened=heap_metrics::Report::open()?.measure("open",None,||Card::open(flash,hardware,key));
   #[cfg(not(feature = "heap-metrics"))]
   let opened=Card::open(flash,hardware,key);
   let card=opened.map_err(|e|format!("{e:?}"))?;
   serve_endpoint(microcard_core::transport::Endpoint::new(card,keys),binary)?;
  }
 },
 Some("serve-jcvm") if a.len()==3=>{
  // A Java Card applet, installed and then handed one APDU per line. The transport is
  // the same text protocol the other serve modes use, so a host driving this needs to
  // know nothing about the engine behind it.
  let block=fs::read(&a[2])?;
  let file=microcard_engine_jcvm::cap::LoadFile::parse(&block).map_err(|e|format!("{e:?}"))?;
  let sizes=microcard_engine_jcvm::applet::Sizes{heap_bytes:64*1024,frame_words:8192,..Default::default()};
  let mut card=microcard_engine_jcvm::applet::Card::new(&file,sizes).map_err(|e|format!("{e:?}"))?;
  let mut hardware=Hardware;
  let mut host=microcard_core::jcvm_services::Services::new(&mut hardware);
  // The standalone simulator installs under the module AID with no privileges.
  let module=file.applets().map_err(|e|format!("{e:?}"))?.iter().next().ok_or("No applet")?.aid;
  let parameters=microcard_core::globalplatform::ApplicationInstall {
   load_aid:file.header().map_err(|e|format!("{e:?}"))?.package_aid,module_aid:module,instance_aid:module,privileges:&[0],parameters:&[],
  }.jcvm_parameters().map_err(|e|format!("{e:?}"))?;
  card.install_instance_with_cancel(&file,&mut host,microcard_engine_jcvm::applet::Installation {
   module_aid:module,instance_aid:module,parameters:&parameters,
  },&mut ||false).map_err(|e|format!("{e:?}"))?;
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
 _=>return Err("commands: keygen PATH | pack ASSEMBLY METADATA DOMAIN INCARNATION_HEX VERSION SEED OUTPUT --explicit-sign | verify PACKAGE | verify-assembly ASSEMBLY | run-mc04 ASSEMBLY METHOD [INT...] | serve MANAGEMENT_KEYS STATE_DIR | serve-jcvm-managed MANAGEMENT_KEYS STATE_DIR | serve-jcvm LOAD_FILE".into())}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use microcard_core::journal::Flash;
    use std::io::{Seek, SeekFrom};

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
