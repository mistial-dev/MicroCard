//! Compiled device-side ABI used by the verified MC04 linker.
use crate::{
    assembly::{Assembly, MethodTypes, StackType},
    mc04_abi::{self, AbiType, Lowering},
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

pub(crate) const SYSTEM_RUNTIME_TOKEN: &[u8] = &[0xb0, 0x3f, 0x5f, 0x7f, 0x11, 0xd5, 0x0a, 0x3a];
pub(crate) use crate::mc04_abi::FRAMEWORK_HASH;

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

fn abi_type(assembly: &Assembly<'_>, value: Option<StackType>, expected: AbiType) -> bool {
    match expected {
        AbiType::Bool | AbiType::Int32 => value == Some(StackType::Int),
        AbiType::ByteArray => value == Some(StackType::Array(1)),
        AbiType::Int32Array => value == Some(StackType::Array(2)),
        AbiType::Reference(full_name) => {
            let Some((namespace, name)) = full_name.rsplit_once('.') else {
                return false;
            };
            reference(assembly, value, namespace, name)
        }
    }
}

fn exact(assembly: &Assembly<'_>, types: &MethodTypes, member: &mc04_abi::Member) -> bool {
    if types.receiver.is_some() != member.receiver
        || types.parameters.len() != member.parameters.len()
        || !member
            .parameters
            .iter()
            .zip(types.parameters.iter().copied())
            .all(|(expected, actual)| abi_type(assembly, Some(actual), *expected))
        || match member.result {
            Some(expected) => !abi_type(assembly, types.result, expected),
            None => types.result.is_some(),
        }
    {
        return false;
    }
    !member.receiver || reference(assembly, types.receiver, member.namespace, member.owner)
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
    if provider.name != mc04_abi::FRAMEWORK_ASSEMBLY {
        return Ok(None);
    }
    if provider.version != [1, 0, 0, 0]
        || provider.flags != 0
        || !provider.public_key_or_token.is_empty()
        || !provider.culture.is_empty()
        || provider.hash_value != FRAMEWORK_HASH
        || owner.namespace != mc04_abi::FRAMEWORK_NAMESPACE
    {
        return Err(Error::Unauthorized);
    }
    let types = assembly.member_types(index)?;
    let definition = mc04_abi::named(
        mc04_abi::FRAMEWORK_ASSEMBLY,
        mc04_abi::FRAMEWORK_NAMESPACE,
        owner.name,
        member.name,
    )
    .find(|definition| exact(assembly, &types, definition))
    .ok_or(Error::Unauthorized)?;
    let binding = match definition.lowering {
        Lowering::Native(id) => Import::Native(id),
        Lowering::CurrentDomain => Import::CurrentDomain,
        Lowering::DomainKeys => Import::DomainKeys,
        Lowering::DomainStorage => Import::DomainStorage,
    };
    Ok(Some(binding))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn compiled_consumer_uses_current_bulk_imports() {
        let assembly =
            Assembly::parse(include_bytes!("../../../fuzz/fixtures/kdf108_consumer.mca")).unwrap();
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
        let assembly =
            Assembly::parse(include_bytes!("../../../fuzz/fixtures/cryptography.mca")).unwrap();
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
        assert!(native.ends_with(&[55, 56, 57, 58, 59, 60]));
    }
}
