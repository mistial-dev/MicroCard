//! SCP03 1.1.2 S8, §§6.2.1–6.2.6. Basic logical channel only.
use crate::{
    apdu::Command,
    crypto::{CryptoProvider, SoftwareCrypto},
    journal::JournalKey,
    Error, Result,
};
use alloc::{borrow::Cow, vec::Vec};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
#[cfg(feature = "scp03-s16")]
compile_error!(
    "scp03-s16 is not implemented yet: the command MAC and challenge widths are still S8"
);
#[cfg(feature = "scp03-pseudo-random")]
compile_error!(
    "scp03-pseudo-random is not implemented yet: the sequence counter has no durable store"
);

/// The SCP03 `i` parameter this build advertises, SCP03 1.1.2.6 Table 5-1.
///
/// Derived from the enabled capabilities rather than written down, so the value reported
/// in the INITIALIZE UPDATE key information, the card recognition data and the SSD
/// install parameters can never claim a mode the build does not implement.
pub const SCP03_I: u8 = (if cfg!(feature = "scp03-s16") { 0x01 } else { 0 })
    | (if cfg!(feature = "scp03-pseudo-random") { 0x10 } else { 0 })
    | (if cfg!(feature = "scp03-rmac") { 0x20 } else { 0 })
    | (if cfg!(feature = "scp03-renc") { 0x40 } else { 0 });

/// Security level bits this build honours in EXTERNAL AUTHENTICATE P1, Table 7-6.
///
/// Command integrity and command confidentiality are always available. Response
/// integrity and response confidentiality follow the advertised capabilities, so a
/// session asking for protection this build cannot apply is refused rather than served
/// with less protection than it requested.
pub const SUPPORTED_SECURITY_LEVEL: u8 = 0x03
    | (if cfg!(feature = "scp03-rmac") { 0x10 } else { 0 })
    | (if cfg!(feature = "scp03-renc") { 0x20 } else { 0 });

/// S16 doubles every challenge, cryptogram and MAC, SCP03 1.1.2.6 §6.2.2 and §6.2.4.
pub const S16: bool = cfg!(feature = "scp03-s16");

/// Challenge and cryptogram width in bytes.
pub const CHALLENGE_BYTES: usize = if S16 { 16 } else { 8 };

/// Transmitted C-MAC and R-MAC width in bytes.
pub const MAC_BYTES: usize = if S16 { 16 } else { 8 };

/// The KDF `L` parameter for challenges and cryptograms, in bits.
pub const CRYPTOGRAM_BITS: u16 = if S16 { 128 } else { 64 };

/// Management commands require at least command integrity. Package signatures authorize
/// the code itself, so command encryption stays the caller's choice.
pub const MANAGEMENT_SECURITY_LEVEL: u8 = 0x01;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Keys {
    pub enc: [u8; 16],
    pub mac: [u8; 16],
}
impl Keys {
    pub fn storage_key(&self) -> JournalKey {
        self.storage_key_with(&mut SoftwareCrypto).unwrap()
    }

    pub fn storage_key_with(&self, provider: &mut impl CryptoProvider) -> Result<JournalKey> {
        let mut output = JournalKey::zeroed();
        provider.aes_cmac_parts_into(
            &self.enc,
            &[b"MicroCard journal AEAD v1\0", &self.mac],
            output.as_mut(),
        )?;
        Ok(output)
    }
}
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Session {
    enc: [u8; 16],
    mac: [u8; 16],
    rmac: [u8; 16],
    chain: [u8; 16],
    host: [u8; 8],
    counter: u32,
    level: u8,
    active: bool,
}
/// Can only originate from an authenticated command, and is consumed by dispatch.
pub struct Verified<'a> {
    pub(crate) command: Command<'a>,
    pub(crate) level: u8,
}
impl Verified<'_> {
    pub fn command(&self) -> &Command<'_> {
        &self.command
    }
    pub fn level(&self) -> u8 {
        self.level
    }
}
impl Session {
    pub fn initiate(keys: &Keys, host: [u8; 8], card: [u8; 8]) -> (Self, [u8; 8]) {
        Self::initiate_with(keys, host, card, &mut SoftwareCrypto).unwrap()
    }

    pub fn initiate_with(
        keys: &Keys,
        host: [u8; 8],
        card: [u8; 8],
        provider: &mut impl CryptoProvider,
    ) -> Result<(Self, [u8; 8])> {
        let context = [&host[..], &card[..]];
        let enc = Zeroizing::new(derive_with(provider, &keys.enc, 4, 128, &context)?);
        let mac = Zeroizing::new(derive_with(provider, &keys.mac, 6, 128, &context)?);
        let rmac = Zeroizing::new(derive_with(provider, &keys.mac, 7, 128, &context)?);
        let crypt_material = Zeroizing::new(derive_with(provider, &mac, 0, 64, &context)?);
        let crypt = crypt_material[..8]
            .try_into()
            .unwrap();
        let host_material = Zeroizing::new(derive_with(provider, &mac, 1, 64, &context)?);
        let host = host_material[..8]
            .try_into()
            .unwrap();
        Ok((
            Self {
                enc: *enc,
                mac: *mac,
                rmac: *rmac,
                host,
                chain: [0; 16],
                counter: 0,
                level: 0,
                active: false,
            },
            crypt,
        ))
    }
    pub fn authenticate(&mut self, c: &Command<'_>) -> Result<()> {
        self.authenticate_with(c, &mut SoftwareCrypto)
    }

    pub fn authenticate_with(
        &mut self,
        c: &Command<'_>,
        provider: &mut impl CryptoProvider,
    ) -> Result<()> {
        let result = (|| {
            if self.active
                || c.cla != 0x84
                || c.ins != 0x82
                || c.p2 != 0
                || c.data.len() != 16
            {
                return Err(Error::Authentication);
            }
            let payload_len = self.check_mac_with(c, provider)?;
            if !bool::from(c.data[..payload_len].ct_eq(&self.host)) {
                return Err(Error::Authentication);
            }
            // The security level is policy rather than authenticity, so it is checked
            // after the host cryptogram. An unauthenticated caller then learns nothing
            // about which modes this build offers.
            if c.p1 & !SUPPORTED_SECURITY_LEVEL != 0 {
                return Err(Error::Unsupported);
            }
            self.level = c.p1;
            self.active = true;
            Ok(())
        })();
        if result.is_err() {
            self.zeroize()
        }
        result
    }
    fn check_mac_with(
        &mut self,
        c: &Command<'_>,
        provider: &mut impl CryptoProvider,
    ) -> Result<usize> {
        if c.cla != 0x84 || c.data.len() < 8 || c.data.len() > 255 {
            return Err(Error::Authentication);
        }
        let n = c.data.len() - 8;
        let header = [c.cla, c.ins, c.p1, c.p2, c.data.len() as u8];
        let mut mac = [0; 16];
        provider.aes_cmac_parts_into(&self.mac, &[&self.chain, &header, &c.data[..n]], &mut mac)?;
        if !bool::from(mac[..8].ct_eq(&c.data[n..])) {
            return Err(Error::Authentication);
        }
        self.chain = mac;
        Ok(n)
    }
    pub fn unwrap<'a>(&mut self, c: Command<'a>) -> Result<Verified<'a>> {
        self.unwrap_with(c, &mut SoftwareCrypto)
    }

    pub fn unwrap_with<'a>(
        &mut self,
        mut c: Command<'a>,
        provider: &mut impl CryptoProvider,
    ) -> Result<Verified<'a>> {
        let result = (|| {
            if !self.active {
                return Err(Error::Unauthorized);
            }
            let payload_len = self.check_mac_with(&c, provider)?;
            c.data = match core::mem::replace(&mut c.data, Cow::Borrowed(&[])) {
                Cow::Borrowed(data) => Cow::Borrowed(&data[..payload_len]),
                Cow::Owned(mut data) => {
                    data.truncate(payload_len);
                    Cow::Owned(data)
                }
            };
            self.counter = self.counter.checked_add(1).ok_or(Error::Authentication)?;
            if self.level & 2 != 0 && !c.data.is_empty() {
                let mut iv = [0; 16];
                iv[12..].copy_from_slice(&self.counter.to_be_bytes());
                provider.aes128_encrypt_block_in_place(&self.enc, &mut iv)?;
                let mut plaintext = crate::crypto::zeroizing_buffer(c.data.len())?;
                let written = match provider.aes_cbc_decrypt(&self.enc, iv, &c.data, &mut plaintext)
                {
                    Ok(written) => written,
                    Err(error) => return Err(error),
                };
                if written > plaintext.len() {
                    return Err(Error::Native);
                }
                plaintext.truncate(written);
                c.data = Cow::Owned(core::mem::take(&mut *plaintext));
            }
            c.cla = 0x80;
            Ok(Verified {
                command: c,
                level: self.level,
            })
        })();
        if result.is_err() {
            self.zeroize()
        }
        result
    }
    pub fn response(&mut self, data: &[u8], sw: u16) -> Result<Vec<u8>> {
        self.response_with(data, sw, &mut SoftwareCrypto)
    }

    pub fn response_with(
        &mut self,
        data: &[u8],
        sw: u16,
        provider: &mut impl CryptoProvider,
    ) -> Result<Vec<u8>> {
        let result = (|| {
            if !self.active {
                return Err(Error::Unauthorized);
            }
            // An error status word carries neither a MAC nor encryption, SCP03 §6.2.5.
            let protected = sw == 0x9000 || sw >> 8 == 0x62 || sw >> 8 == 0x63;
            let rmac = protected && self.level & 0x10 != 0;
            // A response with no data field is never encrypted, SCP03 §6.2.7.
            let renc = protected && self.level & 0x20 != 0 && !data.is_empty();
            let mac_len = if rmac { MAC_BYTES } else { 0 };
            let body_len = if renc {
                crate::crypto::cbc_encrypted_len(data.len())?
            } else if protected {
                data.len()
            } else {
                0
            };
            // Two bytes of the budget belong to the status word.
            if body_len + mac_len + 2 > crate::hal::MAX_SHORT_RESPONSE_BYTES {
                return Err(Error::Bounds);
            }
            // The response ICV reuses the counter block of the command being answered,
            // with the most significant byte set so it can never collide with the
            // command ICV, SCP03 §6.2.7.
            let ciphertext = if renc {
                let mut iv = [0; 16];
                iv[0] = 0x80;
                iv[12..].copy_from_slice(&self.counter.to_be_bytes());
                provider.aes128_encrypt_block_in_place(&self.enc, &mut iv)?;
                let mut buffer = crate::crypto::zeroizing_buffer(body_len)?;
                let written = provider.aes_cbc_encrypt(&self.enc, iv, data, &mut buffer)?;
                buffer.truncate(written);
                Some(buffer)
            } else {
                None
            };
            let body: &[u8] = match ciphertext.as_deref() {
                Some(encrypted) => encrypted,
                None if protected => data,
                None => &[],
            };
            let mut out = Vec::new();
            out.try_reserve_exact(2 + body.len() + mac_len)
                .map_err(|_| Error::Quota)?;
            if protected {
                out.extend_from_slice(body);
                if rmac {
                    // The R-MAC covers the ciphered data field, so it is computed after
                    // encryption, SCP03 §6.2.7.
                    let status = sw.to_be_bytes();
                    let mut mac = [0; 16];
                    provider.aes_cmac_parts_into(
                        &self.rmac,
                        &[&self.chain, body, &status],
                        &mut mac,
                    )?;
                    out.extend_from_slice(&mac[..MAC_BYTES]);
                }
            }
            out.extend_from_slice(&sw.to_be_bytes());
            Ok(out)
        })();
        if result.is_err() {
            self.zeroize();
        }
        result
    }
}

fn derive_with(
    provider: &mut impl CryptoProvider,
    key: &[u8; 16],
    constant: u8,
    bits: u16,
    context: &[&[u8]; 2],
) -> Result<[u8; 16]> {
    let mut header = [0; 16];
    header[11] = constant;
    header[13..15].copy_from_slice(&bits.to_be_bytes());
    header[15] = 1;
    let mut output = Zeroizing::new([0; 16]);
    provider.aes_cmac_parts_into(
        key,
        &[header.as_slice(), context[0], context[1]],
        &mut output,
    )?;
    Ok(*output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex<const N: usize>(value: &str) -> [u8; N] {
        let mut output = [0; N];
        assert_eq!(value.len(), N * 2);
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let digit = |value| match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                b'A'..=b'F' => value - b'A' + 10,
                _ => panic!("hex fixture"),
            };
            output[index] = digit(pair[0]) << 4 | digit(pair[1]);
        }
        output
    }

    #[derive(Default)]
    struct RecordingProvider {
        cmacs: usize,
        blocks: usize,
        decrypts: usize,
    }

    impl CryptoProvider for RecordingProvider {
        fn aes_cmac_parts_into(
            &mut self,
            key: &[u8; 16],
            parts: &[&[u8]],
            output: &mut [u8; 16],
        ) -> Result<()> {
            self.cmacs += 1;
            *output = crate::crypto::cmac_parts(key, parts);
            Ok(())
        }

        fn aes128_encrypt_block_in_place(
            &mut self,
            key: &[u8; 16],
            block: &mut [u8; 16],
        ) -> Result<()> {
            self.blocks += 1;
            *block = crate::crypto::block(key, *block);
            Ok(())
        }

        fn aes_cbc_decrypt(
            &mut self,
            key: &[u8; 16],
            iv: [u8; 16],
            data: &[u8],
            output: &mut [u8],
        ) -> Result<usize> {
            self.decrypts += 1;
            crate::crypto::decrypt_into(key, iv, data, output)
        }
    }

    #[test]
    fn gp4net_vectors_cover_session_derivation_and_cryptograms() {
        // Independently generated Gp4Net fixtures implementing SCP03 1.1.2
        // section 4.1.5. The project author authorized their use here.
        for (keys, host, card, expected_enc, expected_mac, expected_rmac, expected_card, expected_host) in [
            (
                Keys {
                    enc: hex("000102030405060708090A0B0C0D0E0F"),
                    mac: hex("101112131415161718191A1B1C1D1E1F"),
                },
                hex("0001020304050607"),
                hex("08090A0B0C0D0E0F"),
                hex("3619112820D79FF81146E6862151F521"),
                hex("E2B6C0D5DC55B27602375D7A983A2B3C"),
                hex("35210536E8D79B6574FC6F8B6049630D"),
                hex("6E3E560916763FAA"),
                hex("C44D56DED351F5A4"),
            ),
            (
                Keys {
                    enc: [0; 16],
                    mac: [0; 16],
                },
                [0; 8],
                [0; 8],
                hex("D119A7CCA75F050B4F306C8E1E5CC554"),
                hex("78C41DD9D3CCFA9814C3B128FB0BB166"),
                hex("B7698E3A4E8C6AE05E8D8C9A533CA83E"),
                hex("D2119C5615BCA32C"),
                hex("A6C824ACA566F3FD"),
            ),
        ] {
            let (session, card_cryptogram) = Session::initiate(&keys, host, card);
            assert_eq!(session.enc, expected_enc);
            assert_eq!(session.mac, expected_mac);
            assert_eq!(session.rmac, expected_rmac);
            assert_eq!(card_cryptogram, expected_card);
            assert_eq!(session.host, expected_host);
        }
    }

    #[test]
    fn globalplatformpro_trace_authenticates_and_chains_first_command() {
        // Captured by GlobalPlatformPro against a physical SCP03 card. The
        // second MAC proves the complete, untransmitted C-MAC chain agrees.
        let keys = Keys {
            enc: hex("404142434445464748494A4B4C4D4E4F"),
            mac: hex("404142434445464748494A4B4C4D4E4F"),
        };
        let (mut session, card_cryptogram) = Session::initiate(
            &keys,
            hex("6140423CDFBD1638"),
            hex("D9DB42088EC157E7"),
        );
        assert_eq!(session.enc, hex("8F68D7056FE602D97FF70BFA36D87961"));
        assert_eq!(session.mac, hex("AA133569FEC01F8D1BDA168939E90C2E"));
        assert_eq!(session.rmac, hex("05B237DF134CD46B7B13DF0BF9EAE35D"));
        assert_eq!(card_cryptogram, hex("3482F0E96DBF633B"));
        assert_eq!(session.host, hex("05527F7CFB17ECD2"));

        let external = hex::<21>("848201001005527F7CFB17ECD2B596B1DFB99B480F");
        session.authenticate(&Command::parse(&external).unwrap()).unwrap();

        let secured = hex::<16>("84F280020A4F0022CC12E4A1CE233A00");
        let verified = session.unwrap(Command::parse(&secured).unwrap()).unwrap();
        assert_eq!(verified.level(), 0x01);
        assert_eq!(verified.command().cla, 0x80);
        assert_eq!(verified.command().data.as_ref(), [0x4f, 0x00]);
        assert_eq!(verified.command().le, Some(256));
    }

    #[test]
    fn globalplatformpro_trace_decrypts_first_level03_command() {
        let keys = Keys {
            enc: hex("404142434445464748494A4B4C4D4E4F"),
            mac: hex("404142434445464748494A4B4C4D4E4F"),
        };
        let (mut session, card_cryptogram) = Session::initiate(
            &keys,
            hex("F5E88C6C30039A53"),
            hex("0D607A25D729A20F"),
        );
        assert_eq!(card_cryptogram, hex("7E793686DEE77FAF"));

        let external = hex::<22>("84820300103B50EF3764CCDD83AF26B8D11ED7034000");
        session.authenticate(&Command::parse(&external).unwrap()).unwrap();
        let secured =
            hex::<30>("84F280021847D799BDC908166D61B7CEAFD6205F731A7B8648F31BC58000");
        let verified = session.unwrap(Command::parse(&secured).unwrap()).unwrap();
        assert_eq!(verified.level(), 0x03);
        assert_eq!(verified.command().data.as_ref(), [0x4f, 0x00]);
        assert_eq!(verified.command().le, Some(256));
    }

    // Security level 0x11 needs response integrity, so this build must offer it.
    #[cfg(feature = "scp03-rmac")]
    #[test]
    fn globalplatformpro_trace_emits_first_level11_response_mac() {
        let keys = Keys {
            enc: hex("404142434445464748494A4B4C4D4E4F"),
            mac: hex("404142434445464748494A4B4C4D4E4F"),
        };
        let (mut session, card_cryptogram) = Session::initiate(
            &keys,
            hex("578E2189E0165680"),
            hex("C97B56DFA8530D14"),
        );
        assert_eq!(card_cryptogram, hex("90F014B782326233"));

        let external = hex::<22>("848211001014D85FD473773D1ADFF1083C74C9C21D00");
        session.authenticate(&Command::parse(&external).unwrap()).unwrap();
        let secured = hex::<16>("84F280020A4F004927FCE085AD3AC600");
        let verified = session.unwrap(Command::parse(&secured).unwrap()).unwrap();
        assert_eq!(verified.command().data.as_ref(), [0x4f, 0x00]);

        let data = hex::<40>(
            "E3264F08A0000001510000009F700101C5039EFE80C407A0\
             000001515350CC08A000000151000000",
        );
        assert_eq!(
            session.response(&data, 0x9000).unwrap(),
            hex::<50>(
                "E3264F08A0000001510000009F700101C5039EFE80C407A0\
                 000001515350CC08A0000001510000006BAE3EFF2B476D049000",
            )
        );
    }

    #[test]
    fn gp4net_level13_vector_decrypts_command_and_emits_response_mac() {
        // Independently generated by the user-authorized Gp4Net SCP03
        // implementation with fixed session keys and initial chaining value.
        #[derive(serde::Deserialize)]
        struct Vector {
            security_level: alloc::string::String,
            session_enc: alloc::string::String,
            session_mac: alloc::string::String,
            session_rmac: alloc::string::String,
            initial_chain: alloc::string::String,
            plain_command: alloc::string::String,
            secured_command: alloc::string::String,
            command_chain: alloc::string::String,
            plain_response: alloc::string::String,
            secured_response: alloc::string::String,
        }
        let vector: Vector = serde_json::from_str(include_str!(
            "../tests/vectors/scp03_gp4net_level13.json"
        ))
        .unwrap();
        assert_eq!(vector.security_level, "13");
        assert_eq!(vector.plain_command, "80E2000003010203");
        let make_session = || Session {
            enc: hex(&vector.session_enc),
            mac: hex(&vector.session_mac),
            rmac: hex(&vector.session_rmac),
            chain: hex(&vector.initial_chain),
            host: [0; 8],
            counter: 0,
            level: 0x13,
            active: true,
        };
        let secured = hex::<29>(&vector.secured_command);
        let mut tampered = secured;
        tampered[28] ^= 1;
        let mut rejected = make_session();
        assert_eq!(
            rejected.unwrap(Command::parse(&tampered).unwrap()).err(),
            Some(Error::Authentication)
        );
        assert!(!rejected.active);

        let mut session = make_session();
        let verified = session.unwrap(Command::parse(&secured).unwrap()).unwrap();
        assert_eq!(verified.level(), 0x13);
        assert_eq!(verified.command().cla, 0x80);
        assert_eq!(verified.command().ins, 0xe2);
        assert_eq!(verified.command().data.as_ref(), [1, 2, 3]);
        assert_eq!(
            session.chain,
            hex::<16>(&vector.command_chain)
        );
        assert_eq!(vector.plain_response, "A1A2A39000");
        assert_eq!(
            session.response(&[0xa1, 0xa2, 0xa3], 0x9000).unwrap(),
            hex::<13>(&vector.secured_response)
        );
    }

    #[cfg(feature = "scp03-renc")]
    #[test]
    fn level33_encrypts_response_data_and_macs_the_ciphertext() {
        let keys = Keys {
            enc: [0x11; 16],
            mac: [0x22; 16],
        };
        let (mut session, _) = Session::initiate(&keys, [0x31; 8], [0x42; 8]);
        session.active = true;
        session.level = 0x33;
        session.counter = 7;
        let plaintext = b"secret response";

        let response = session.response(plaintext, 0x9000).unwrap();

        // Ciphered data, then the R-MAC, then the status word.
        let body_len = crate::crypto::cbc_encrypted_len(plaintext.len()).unwrap();
        assert_eq!(response.len(), body_len + MAC_BYTES + 2);
        let body = &response[..body_len];
        assert_eq!(&response[response.len() - 2..], &[0x90, 0x00]);
        assert_ne!(body, &plaintext[..], "response data must not travel in clear");
        assert_eq!(body_len % 16, 0, "ciphertext is whole blocks");

        // The R-MAC covers the ciphertext, not the plaintext, SCP03 §6.2.7.
        let expected = crate::crypto::cmac_parts(
            &session.rmac,
            &[&session.chain, body, &0x9000u16.to_be_bytes()],
        );
        assert_eq!(
            &response[body_len..body_len + MAC_BYTES],
            &expected[..MAC_BYTES]
        );

        // The response ICV is the command counter block with the top byte set, so
        // decrypting with that recipe recovers the plaintext.
        let mut iv = [0; 16];
        iv[0] = 0x80;
        iv[12..].copy_from_slice(&7u32.to_be_bytes());
        let iv = crate::crypto::block(&session.enc, iv);
        let mut recovered = alloc::vec![0; body_len];
        let written =
            crate::crypto::decrypt_into(&session.enc, iv, body, &mut recovered).unwrap();
        assert_eq!(&recovered[..written], plaintext);

        // A command ICV would use a zero top byte, so it must not decrypt this.
        let mut command_iv = [0; 16];
        command_iv[12..].copy_from_slice(&7u32.to_be_bytes());
        let command_iv = crate::crypto::block(&session.enc, command_iv);
        assert_ne!(command_iv, iv, "response and command ICVs differ");
    }

    #[cfg(feature = "scp03-renc")]
    #[test]
    fn level33_leaves_empty_and_error_responses_unencrypted() {
        let keys = Keys {
            enc: [0x11; 16],
            mac: [0x22; 16],
        };
        let (mut session, _) = Session::initiate(&keys, [0x31; 8], [0x42; 8]);
        session.active = true;
        session.level = 0x33;

        // No data field means no encryption, only integrity, SCP03 §6.2.7.
        let empty = session.response(&[], 0x9000).unwrap();
        assert_eq!(empty.len(), MAC_BYTES + 2);
        assert_eq!(&empty[empty.len() - 2..], &[0x90, 0x00]);

        // An error status word carries neither a MAC nor encryption, SCP03 §6.2.5.
        let error = session.response(&[], 0x6a88).unwrap();
        assert_eq!(error, alloc::vec![0x6a, 0x88]);
        let error_with_data = session.response(b"ignored", 0x6982).unwrap();
        assert_eq!(error_with_data, alloc::vec![0x69, 0x82]);
    }

    #[test]
    fn advertised_modes_match_the_capabilities_this_build_has() {
        // The i parameter and the accepted security levels are both derived from the
        // feature set. This pins the two together so a build can never advertise a mode
        // it cannot apply, which would leave a host protected less than it asked for.
        let rmac = cfg!(feature = "scp03-rmac");
        let renc = cfg!(feature = "scp03-renc");
        assert_eq!(SCP03_I & 0x20 != 0, rmac, "i R-MAC bit tracks the feature");
        assert_eq!(SCP03_I & 0x40 != 0, renc, "i R-ENCRYPTION bit tracks the feature");
        assert_eq!(SCP03_I & 0x01 != 0, S16, "i S16 bit tracks the feature");
        assert_eq!(
            SCP03_I & 0x10 != 0,
            cfg!(feature = "scp03-pseudo-random"),
            "i pseudo-random bit tracks the feature"
        );
        assert_eq!(SUPPORTED_SECURITY_LEVEL & 0x10 != 0, rmac);
        assert_eq!(SUPPORTED_SECURITY_LEVEL & 0x20 != 0, renc);
        // Command integrity and confidentiality are not optional.
        assert_eq!(SUPPORTED_SECURITY_LEVEL & 0x03, 0x03);
        // Table 5-1 reserves b7 b6 = 10, so response encryption always carries R-MAC.
        assert!(!renc || rmac, "R-ENCRYPTION without R-MAC is a reserved encoding");
        const { assert!(SCP03_I & 0x40 == 0 || SCP03_I & 0x20 != 0) };
        // Widths follow S16 together, never independently.
        assert_eq!(CHALLENGE_BYTES, if S16 { 16 } else { 8 });
        assert_eq!(MAC_BYTES, if S16 { 16 } else { 8 });
        assert_eq!(CRYPTOGRAM_BITS, if S16 { 128 } else { 64 });
        // Every RFU bit stays clear.
        assert_eq!(SCP03_I & 0x8e, 0, "RFU and reserved i bits stay zero");
    }

    #[test]
    fn journal_key_depends_on_both_management_keys() {
        let base = Keys {
            enc: [0x11; 16],
            mac: [0x22; 16],
        }
        .storage_key();
        let changed_enc = Keys {
            enc: [0x12; 16],
            mac: [0x22; 16],
        }
        .storage_key();
        let changed_mac = Keys {
            enc: [0x11; 16],
            mac: [0x23; 16],
        }
        .storage_key();
        assert_ne!(base, changed_enc);
        assert_ne!(base, changed_mac);
    }

    #[test]
    fn scp03_uses_provider_for_derivation_secure_messaging_and_storage() {
        let keys = Keys {
            enc: [0x11; 16],
            mac: [0x22; 16],
        };
        let mut provider = RecordingProvider::default();
        let _ = keys.storage_key_with(&mut provider).unwrap();
        let (mut session, _) =
            Session::initiate_with(&keys, [0x31; 8], [0x42; 8], &mut provider).unwrap();
        assert_eq!(provider.cmacs, 6);

        session.active = true;
        session.level = 0x13;
        let plaintext = [0x01, 0x02, 0x03];
        let mut counter_block = [0; 16];
        counter_block[12..].copy_from_slice(&1_u32.to_be_bytes());
        let iv = crate::crypto::block(&session.enc, counter_block);
        let mut ciphertext = [0; 16];
        let written =
            crate::crypto::encrypt_into(&session.enc, iv, &plaintext, &mut ciphertext).unwrap();
        let mut command = Command {
            cla: 0x84,
            ins: 0xca,
            p1: 0,
            p2: 0,
            data: ciphertext[..written].to_vec().into(),
            le: None,
        };
        let mut mac_input = session.chain.to_vec();
        mac_input.extend_from_slice(&[
            command.cla,
            command.ins,
            command.p1,
            command.p2,
            (command.data.len() + 8) as u8,
        ]);
        mac_input.extend_from_slice(&command.data);
        let mac = crate::crypto::cmac(&session.mac, &mac_input);
        command.data.to_mut().extend_from_slice(&mac[..8]);

        let verified = session.unwrap_with(command, &mut provider).unwrap();
        assert_eq!(verified.command().data.as_ref(), plaintext);
        assert_eq!((provider.blocks, provider.decrypts), (1, 1));
        let response = session.response_with(b"ok", 0x9000, &mut provider).unwrap();
        assert_eq!(response.len(), 12);
        assert_eq!(provider.cmacs, 8);
    }

    #[test]
    fn authenticated_plaintext_reuses_the_command_buffer() {
        let keys = Keys {
            enc: [0x11; 16],
            mac: [0x22; 16],
        };
        let (mut session, _) = Session::initiate(&keys, [0x31; 8], [0x42; 8]);
        session.active = true;
        session.level = 0x01;
        let payload = [0x01, 0x02, 0x03];
        let mut mac_input = session.chain.to_vec();
        mac_input.extend_from_slice(&[0x84, 0xca, 0, 0, (payload.len() + 8) as u8]);
        mac_input.extend_from_slice(&payload);
        let mac = crate::crypto::cmac(&session.mac, &mac_input);
        let mut raw = alloc::vec![0x84, 0xca, 0, 0, (payload.len() + 8) as u8];
        raw.extend_from_slice(&payload);
        raw.extend_from_slice(&mac[..8]);
        raw.push(0);
        let command = Command::parse(&raw).unwrap();
        assert!(matches!(command.data, Cow::Borrowed(_)));
        let buffer = command.data.as_ptr();

        let verified = session.unwrap(command).unwrap();

        assert_eq!(verified.command().data.as_ref(), [0x01, 0x02, 0x03]);
        assert_eq!(verified.command().data.as_ptr(), buffer);
        assert_eq!(verified.command().le, Some(256));
    }

    #[test]
    fn scp03_preserves_provider_failures() {
        struct FailingProvider;
        impl CryptoProvider for FailingProvider {
            fn aes_cmac_parts_into(
                &mut self,
                _: &[u8; 16],
                _: &[&[u8]],
                _: &mut [u8; 16],
            ) -> Result<()> {
                Err(Error::Native)
            }
        }

        let keys = Keys {
            enc: [0x11; 16],
            mac: [0x22; 16],
        };
        assert!(matches!(
            keys.storage_key_with(&mut FailingProvider),
            Err(Error::Native)
        ));
        assert!(matches!(
            Session::initiate_with(&keys, [0x31; 8], [0x42; 8], &mut FailingProvider,),
            Err(Error::Native)
        ));

        let (mut session, _) = Session::initiate(&keys, [0x31; 8], [0x42; 8]);
        session.active = true;
        session.level = 0x11;
        assert!(matches!(
            session.response_with(b"result", 0x9000, &mut FailingProvider),
            Err(Error::Native)
        ));
        assert!(!session.active);
        assert_eq!(session.enc, [0; 16]);
        assert_eq!(session.mac, [0; 16]);
        assert_eq!(session.rmac, [0; 16]);
    }
}
