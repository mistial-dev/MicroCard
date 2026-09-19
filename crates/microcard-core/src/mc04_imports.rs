//! Compiled device-side ABI used by the verified MC04 linker.
use crate::{
    assembly::{Assembly, MethodTypes, StackType},
    Error, Result,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Import {
    ObjectConstructor,
    CurrentDomain,
    DomainStorage,
    DomainKeys,
    Native(u8),
}

pub(crate) const SYSTEM_RUNTIME_TOKEN: &[u8] =
    &[0xb0, 0x3f, 0x5f, 0x7f, 0x11, 0xd5, 0x0a, 0x3a];
/// Stable identity of the reviewed MicroCard.Framework 1.0 device ABI.
/// Host tooling separately authenticates the framework DLL by file digest.
pub(crate) const FRAMEWORK_HASH: &[u8] = &[
    0xe9, 0xb2, 0x76, 0xdc, 0x44, 0x59, 0xe6, 0xff, 0xb3, 0x7f, 0x91, 0x19, 0x87, 0x4b,
    0x50, 0x53, 0xb1, 0x4c, 0xd0, 0xb3, 0x48, 0x4a, 0x01, 0xc7, 0x03, 0x16, 0xdd, 0x80,
    0xfb, 0x08, 0x36, 0x5a,
];

fn reference(
    assembly: &Assembly<'_>,
    value: Option<StackType>,
    namespace: &str,
    name: &str,
) -> bool {
    let Some(StackType::Ref(token)) = value else {
        return false;
    };
    let table = (token >> 16) as u8;
    let row = token as u16;
    table == 1
        && assembly
            .type_ref(row)
            .is_ok_and(|ty| ty.namespace == namespace && ty.name == name)
}

fn exact(
    types: &MethodTypes,
    receiver: bool,
    parameters: &[StackType],
    result: Option<StackType>,
) -> bool {
    types.receiver.is_some() == receiver && types.parameters == parameters && types.result == result
}

/// Resolve only the immutable MicroCard.Framework 1.0 ABI. Matching names do
/// not bind unless assembly identity and the complete managed shape also match.
pub fn resolve(assembly: &Assembly<'_>, index: u16) -> Result<Option<Import>> {
    let member = assembly.member_ref(index)?;
    if member.parent.table != 1 {
        return Ok(None);
    }
    let owner = assembly.type_ref(member.parent.row)?;
    if owner.scope.table != 35 {
        return Ok(None);
    }
    let provider = assembly.assembly_ref(owner.scope.row)?;
    if provider.name == "System.Runtime" {
        if provider.version != [10, 0, 0, 0]
            || provider.flags != 0
            || provider.public_key_or_token != SYSTEM_RUNTIME_TOKEN
            || !provider.culture.is_empty()
            || !provider.hash_value.is_empty()
            || owner.namespace != "System"
            || owner.name != "Object"
            || member.name != ".ctor"
        {
            return Err(Error::Unauthorized);
        }
        let types = assembly.member_types(index)?;
        return if types.receiver.is_some() && types.parameters.is_empty() && types.result.is_none()
        {
            Ok(Some(Import::ObjectConstructor))
        } else {
            Err(Error::Unauthorized)
        };
    }
    if provider.name != "MicroCard.Framework" {
        return Ok(None);
    }
    if provider.version != [1, 0, 0, 0]
        || provider.flags != 0
        || !provider.public_key_or_token.is_empty()
        || !provider.culture.is_empty()
        || provider.hash_value != FRAMEWORK_HASH
        || owner.namespace != "MicroCard.Framework"
    {
        return Err(Error::Unauthorized);
    }
    let types = assembly.member_types(index)?;
    let byte_array = StackType::Array(1);
    let int = StackType::Int;
    let binding = match (owner.name, member.name) {
        ("SecurityDomain", "get_Current")
            if types.receiver.is_none()
                && types.parameters.is_empty()
                && reference(
                    assembly,
                    types.result,
                    "MicroCard.Framework",
                    "SecurityDomain",
                ) =>
        {
            Import::CurrentDomain
        }
        ("SecurityDomain", "get_Keys")
            if reference(
                assembly,
                types.receiver,
                "MicroCard.Framework",
                "SecurityDomain",
            ) && types.parameters.is_empty()
                && reference(assembly, types.result, "MicroCard.Framework", "DomainKeys") =>
        {
            Import::DomainKeys
        }
        ("SecurityDomain", "get_Store")
            if reference(
                assembly,
                types.receiver,
                "MicroCard.Framework",
                "SecurityDomain",
            ) && types.parameters.is_empty()
                && reference(
                    assembly,
                    types.result,
                    "MicroCard.Framework",
                    "DomainStorage",
                ) =>
        {
            Import::DomainStorage
        }
        ("DomainStore", "GetInt32") if exact(&types, false, &[int], Some(int)) => Import::Native(3),
        ("DomainStore", "SetInt32") if exact(&types, false, &[int, int], None) => Import::Native(4),
        ("RandomNumber", "GetInt32") if exact(&types, false, &[], Some(int)) => Import::Native(5),
        ("Hardware", "Write") if exact(&types, false, &[int, int], None) => Import::Native(6),
        ("DomainStorage", "GetInt32")
            if reference(
                assembly,
                types.receiver,
                "MicroCard.Framework",
                "DomainStorage",
            ) && types.parameters == [int]
                && types.result == Some(int) =>
        {
            Import::Native(7)
        }
        ("DomainStorage", "SetInt32")
            if reference(
                assembly,
                types.receiver,
                "MicroCard.Framework",
                "DomainStorage",
            ) && types.parameters == [int, int]
                && types.result.is_none() =>
        {
            Import::Native(8)
        }
        ("SecureChannel", "get_SecurityLevel") if exact(&types, false, &[], Some(int)) => {
            Import::Native(9)
        }
        ("SecureChannel", "get_IsAuthenticated") if exact(&types, false, &[], Some(int)) => {
            Import::Native(10)
        }
        ("CommandApdu", "get_Length") if exact(&types, false, &[], Some(int)) => {
            Import::Native(11)
        }
        ("CommandApdu", "CopyTo")
            if exact(&types, false, &[byte_array, int, int, int], None) =>
        {
            Import::Native(12)
        }
        ("ResponseApdu", "Write")
            if exact(&types, false, &[byte_array, int, int], None) =>
        {
            Import::Native(13)
        }
        ("Cryptography", "Sha256") if exact(&types, false, &[byte_array], Some(byte_array)) => {
            Import::Native(20)
        }
        ("Cryptography", "Sha256Into")
            if exact(
                &types,
                false,
                &[byte_array, int, int, byte_array, int],
                Some(int),
            ) =>
        {
            Import::Native(49)
        }
        ("Cryptography", "RandomBytes")
            if exact(&types, false, &[int], Some(byte_array)) =>
        {
            Import::Native(50)
        }
        ("Cryptography", "FixedTimeEquals")
            if exact(
                &types,
                false,
                &[byte_array, int, int, byte_array, int, int],
                Some(int),
            ) =>
        {
            Import::Native(51)
        }
        ("DomainKeys", "Generate")
            if reference(
                assembly,
                types.receiver,
                "MicroCard.Framework",
                "DomainKeys",
            ) && types.parameters == [int, int]
                && reference(assembly, types.result, "MicroCard.Framework", "KeyHandle") =>
        {
            Import::Native(22)
        }
        ("DomainKeys", "Open")
            if reference(
                assembly,
                types.receiver,
                "MicroCard.Framework",
                "DomainKeys",
            ) && types.parameters == [int]
                && reference(assembly, types.result, "MicroCard.Framework", "KeyHandle") =>
        {
            Import::Native(23)
        }
        ("DomainKeys", "Delete")
            if reference(
                assembly,
                types.receiver,
                "MicroCard.Framework",
                "DomainKeys",
            ) && types.parameters == [int]
                && types.result.is_none() =>
        {
            Import::Native(24)
        }
        ("KeyHandle", "HmacSha256" | "AesCmac")
            if reference(assembly, types.receiver, "MicroCard.Framework", "KeyHandle")
                && types.parameters == [byte_array]
                && types.result == Some(byte_array) =>
        {
            Import::Native(if member.name == "HmacSha256" { 25 } else { 26 })
        }
        ("KeyHandle", "EncryptCbc" | "DecryptCbc")
            if reference(assembly, types.receiver, "MicroCard.Framework", "KeyHandle")
                && types.parameters == [byte_array, byte_array]
                && types.result == Some(byte_array) =>
        {
            Import::Native(if member.name == "EncryptCbc" { 27 } else { 28 })
        }
        ("KeyHandle", "EncryptCcm" | "DecryptCcm")
            if reference(assembly, types.receiver, "MicroCard.Framework", "KeyHandle")
                && types.parameters == [byte_array, byte_array, byte_array]
                && types.result == Some(byte_array) =>
        {
            Import::Native(if member.name == "EncryptCcm" { 29 } else { 30 })
        }
        ("KeyHandle", "ExportP256PublicKey")
            if reference(assembly, types.receiver, "MicroCard.Framework", "KeyHandle")
                && types.parameters.is_empty()
                && types.result == Some(byte_array) =>
        {
            Import::Native(35)
        }
        ("KeyHandle", "SignP256")
            if reference(assembly, types.receiver, "MicroCard.Framework", "KeyHandle")
                && types.parameters == [byte_array, int, int]
                && types.result == Some(byte_array) =>
        {
            Import::Native(36)
        }
        ("KeyHandle", "DeriveP256")
            if reference(assembly, types.receiver, "MicroCard.Framework", "KeyHandle")
                && types.parameters == [byte_array]
                && types.result == Some(byte_array) =>
        {
            Import::Native(38)
        }
        ("Cryptography", "VerifyP256")
            if exact(
                &types,
                false,
                &[byte_array, byte_array, byte_array],
                Some(int),
            ) =>
        {
            Import::Native(37)
        }
        ("Cryptography", "FillRandom")
            if exact(&types, false, &[byte_array, int, int], None) =>
        {
            Import::Native(39)
        }
        ("CredentialNative", "Create")
            if exact(
                &types,
                false,
                &[int, byte_array, int, int, int, byte_array, int, int, int],
                None,
            ) =>
        {
            Import::Native(40)
        }
        ("CredentialNative", "Verify")
            if exact(&types, false, &[int, byte_array, int, int], Some(int)) =>
        {
            Import::Native(41)
        }
        ("CredentialNative", "IsVerified") if exact(&types, false, &[int], Some(int)) => {
            Import::Native(42)
        }
        ("CredentialNative", "Change")
            if exact(&types, false, &[int, byte_array, int, int], None) =>
        {
            Import::Native(43)
        }
        ("CredentialNative", "Unblock")
            if exact(
                &types,
                false,
                &[int, byte_array, int, int, byte_array, int, int],
                Some(int),
            ) =>
        {
            Import::Native(44)
        }
        ("CredentialNative", "RetriesRemaining")
            if exact(&types, false, &[int, int], Some(int)) =>
        {
            Import::Native(45)
        }
        ("DomainStorage", "GetBytes")
            if reference(
                assembly,
                types.receiver,
                "MicroCard.Framework",
                "DomainStorage",
            ) && types.parameters == [int]
                && types.result == Some(byte_array) =>
        {
            Import::Native(31)
        }
        ("DomainStorage", "SetBytes")
            if reference(
                assembly,
                types.receiver,
                "MicroCard.Framework",
                "DomainStorage",
            ) && types.parameters == [int, byte_array]
                && types.result.is_none() =>
        {
            Import::Native(32)
        }
        ("DomainStorage", "SetBytes")
            if reference(
                assembly,
                types.receiver,
                "MicroCard.Framework",
                "DomainStorage",
            ) && types.parameters == [int, byte_array, int, int]
                && types.result.is_none() =>
        {
            Import::Native(52)
        }
        ("DomainStorage", "DeleteBytes")
            if reference(
                assembly,
                types.receiver,
                "MicroCard.Framework",
                "DomainStorage",
            ) && types.parameters == [int]
                && types.result.is_none() =>
        {
            Import::Native(33)
        }
        ("DomainStorage", "ContainsBytes")
            if reference(
                assembly,
                types.receiver,
                "MicroCard.Framework",
                "DomainStorage",
            ) && types.parameters == [int]
                && types.result == Some(int) =>
        {
            Import::Native(34)
        }
        ("DomainStorage", "BeginTransaction" | "CommitTransaction" | "AbortTransaction")
            if reference(
                assembly,
                types.receiver,
                "MicroCard.Framework",
                "DomainStorage",
            ) && types.parameters.is_empty()
                && types.result.is_none() =>
        {
            Import::Native(match member.name {
                "BeginTransaction" => 46,
                "CommitTransaction" => 47,
                _ => 48,
            })
        }
        ("ResponseApdu", "SetStatus") if exact(&types, false, &[int], None) => {
            Import::Native(2)
        }
        _ => return Err(Error::Unauthorized),
    };
    Ok(Some(binding))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn compiled_consumer_uses_current_bulk_imports() {
        let assembly = Assembly::parse(include_bytes!(
            "../../../fuzz/fixtures/kdf108_consumer.mca"
        ))
        .unwrap();
        let imports = assembly
            .member_ref_uses()
            .unwrap()
            .into_iter()
            .filter_map(|(member, _)| resolve(&assembly, member).transpose())
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert!(imports.contains(&Import::Native(2)));
        assert!(imports.contains(&Import::Native(11)));
        assert!(imports.contains(&Import::Native(12)));
        assert!(imports.contains(&Import::Native(13)));
        assert!(imports.contains(&Import::Native(22)));
        assert!(imports.contains(&Import::Native(23)));
        assert!(imports.contains(&Import::Native(24)));
    }

    #[test]
    fn compiled_cryptography_facade_uses_the_complete_native_profile() {
        let assembly = Assembly::parse(include_bytes!(
            "../../../fuzz/fixtures/cryptography.mca"
        ))
        .unwrap();
        let mut native = assembly
            .member_ref_uses()
            .unwrap()
            .into_iter()
            .filter_map(|(member, _)| resolve(&assembly, member).transpose())
            .collect::<Result<Vec<_>>>()
            .unwrap()
            .into_iter()
            .filter_map(|import| match import {
                Import::Native(id) => Some(id),
                _ => None,
            })
            .collect::<Vec<_>>();
        native.sort_unstable();
        native.dedup();
        assert_eq!(
            native,
            [20, 22, 23, 24, 25, 26, 27, 28, 29, 30, 35, 36, 37, 38, 39, 49, 50, 51]
        );
    }

    #[test]
    fn compiled_system_cryptography_projections_use_only_the_pinned_framework() {
        let assembly = Assembly::parse(include_bytes!(
            "../../../fuzz/fixtures/cryptography_consumer.mca"
        ))
        .unwrap();
        let assembly_names = (1..=assembly.row_count(35).unwrap())
            .map(|row| assembly.assembly_ref(row).unwrap().name)
            .collect::<Vec<_>>();
        assert!(!assembly_names.contains(&"System.Security.Cryptography"));
        assert!(assembly_names.contains(&"MicroCard.Framework"));
        assert!(assembly
            .member_ref_uses()
            .unwrap()
            .into_iter()
            .any(|(member, _)| resolve(&assembly, member) == Ok(Some(Import::Native(20)))));
        assert!(assembly
            .member_ref_uses()
            .unwrap()
            .into_iter()
            .any(|(member, _)| resolve(&assembly, member) == Ok(Some(Import::Native(50)))));
    }

    #[test]
    fn compiled_transaction_controls_use_the_pinned_native_profile() {
        let assembly = Assembly::parse(include_bytes!(
            "../../../tests/fixtures/transaction_records.mca"
        ))
        .unwrap();
        let mut native = assembly
            .member_ref_uses()
            .unwrap()
            .into_iter()
            .filter_map(|(member, _)| resolve(&assembly, member).transpose())
            .collect::<Result<Vec<_>>>()
            .unwrap()
            .into_iter()
            .filter_map(|import| match import {
                Import::Native(id) => Some(id),
                _ => None,
            })
            .collect::<Vec<_>>();
        native.sort_unstable();
        native.dedup();
        assert!(native.ends_with(&[46, 47, 48]));
    }
}
