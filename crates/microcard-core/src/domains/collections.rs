//! Bounded, sorted collections used by persistent domain state.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct NameMap<V>(pub(super) Vec<(Rc<str>, V)>);

impl<V> Default for NameMap<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> NameMap<V> {
    pub(super) fn new() -> Self {
        Self(Vec::new())
    }

    pub(super) fn position(&self, name: &str) -> core::result::Result<usize, usize> {
        self.0
            .binary_search_by(|(candidate, _)| candidate.as_ref().cmp(name))
    }

    pub(super) fn reserve_entry(&mut self) -> Result<()> {
        if self.0.len() >= MAX_ASSEMBLIES_PER_DOMAIN as usize {
            return Err(Error::Quota);
        }
        if self.0.len() == self.0.capacity() {
            self.0.try_reserve_exact(1).map_err(|_| Error::Quota)?;
        }
        Ok(())
    }

    pub(super) fn reserve_for(&mut self, name: &str) -> Result<()> {
        if self.contains_key(name) {
            Ok(())
        } else {
            self.reserve_entry()
        }
    }

    pub(super) fn insert(&mut self, name: Rc<str>, value: V) -> Result<()> {
        match self.position(name.as_ref()) {
            Ok(index) => {
                self.0[index].1 = value;
                Ok(())
            }
            Err(index) => {
                self.reserve_entry()?;
                self.0.insert(index, (name, value));
                Ok(())
            }
        }
    }

    pub(super) fn get(&self, name: &str) -> Option<&V> {
        self.position(name).ok().map(|index| &self.0[index].1)
    }

    #[cfg(test)]
    pub(super) fn get_mut(&mut self, name: &str) -> Option<&mut V> {
        self.position(name).ok().map(|index| &mut self.0[index].1)
    }

    pub(super) fn get_key_value(&self, name: &str) -> Option<(&Rc<str>, &V)> {
        self.position(name)
            .ok()
            .map(|index| (&self.0[index].0, &self.0[index].1))
    }

    pub(super) fn contains_key(&self, name: &str) -> bool {
        self.position(name).is_ok()
    }

    pub(super) fn len(&self) -> usize {
        self.0.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(super) fn iter(&self) -> core::slice::Iter<'_, (Rc<str>, V)> {
        self.0.iter()
    }

    pub(super) fn iter_mut(&mut self) -> core::slice::IterMut<'_, (Rc<str>, V)> {
        self.0.iter_mut()
    }

    pub(super) fn keys(&self) -> impl Iterator<Item = &Rc<str>> {
        self.0.iter().map(|(name, _)| name)
    }

    pub(super) fn values(&self) -> impl Iterator<Item = &V> {
        self.0.iter().map(|(_, value)| value)
    }
}

#[cfg(test)]
impl<V> core::ops::Index<&str> for NameMap<V> {
    type Output = V;

    fn index(&self, name: &str) -> &Self::Output {
        self.get(name).expect("missing assembly identity")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Domains(pub(super) Vec<(String, Domain)>);

impl Domains {
    pub(super) fn new() -> Self {
        Self(Vec::new())
    }

    pub(super) fn position(&self, id: &str) -> core::result::Result<usize, usize> {
        self.0
            .binary_search_by(|(candidate, _)| candidate.as_str().cmp(id))
    }

    pub(super) fn get(&self, id: &str) -> Option<&Domain> {
        self.position(id).ok().map(|index| &self.0[index].1)
    }

    #[cfg(test)]
    pub(super) fn get_mut(&mut self, id: &str) -> Option<&mut Domain> {
        self.position(id).ok().map(|index| &mut self.0[index].1)
    }

    pub(super) fn get_key_value(&self, id: &str) -> Option<(&String, &Domain)> {
        self.position(id)
            .ok()
            .map(|index| (&self.0[index].0, &self.0[index].1))
    }

    pub(super) fn contains_key(&self, id: &str) -> bool {
        self.position(id).is_ok()
    }

    pub(super) fn insert(&mut self, id: String, domain: Domain) -> Result<Option<Domain>> {
        match self.position(&id) {
            Ok(index) => Ok(Some(core::mem::replace(&mut self.0[index].1, domain))),
            Err(index) => {
                if self.0.len() >= MAX_SSDS {
                    return Err(Error::Quota);
                }
                self.0.try_reserve_exact(1).map_err(|_| Error::Quota)?;
                self.0.insert(index, (id, domain));
                Ok(None)
            }
        }
    }

    pub(super) fn len(&self) -> usize {
        self.0.len()
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(super) fn iter(&self) -> core::slice::Iter<'_, (String, Domain)> {
        self.0.iter()
    }

    pub(super) fn values(&self) -> impl Iterator<Item = &Domain> {
        self.0.iter().map(|(_, domain)| domain)
    }

    pub(super) fn values_mut(&mut self) -> impl Iterator<Item = &mut Domain> {
        self.0.iter_mut().map(|(_, domain)| domain)
    }
}

#[cfg(test)]
impl core::ops::Index<&str> for Domains {
    type Output = Domain;

    fn index(&self, id: &str) -> &Self::Output {
        self.get(id).expect("missing domain")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct IntStore(pub(super) Vec<(i32, i32)>);

impl Drop for IntStore {
    fn drop(&mut self) {
        for value in self.values_mut() {
            value.zeroize();
        }
    }
}

impl IntStore {
    pub(super) fn new() -> Self {
        Self(Vec::new())
    }

    pub(super) fn try_clone_with(
        &self,
        context: &mut crate::fallible_clone::CloneContext,
    ) -> Result<Self> {
        Ok(Self(context.clone_vec(&self.0)?))
    }

    pub(super) fn position(&self, key: i32) -> core::result::Result<usize, usize> {
        self.0
            .binary_search_by_key(&key, |(candidate, _)| *candidate)
    }

    pub(super) fn get(&self, key: &i32) -> Option<&i32> {
        self.position(*key).ok().map(|index| &self.0[index].1)
    }

    pub(super) fn contains_key(&self, key: &i32) -> bool {
        self.position(*key).is_ok()
    }

    pub(super) fn insert(&mut self, key: i32, value: i32) -> Result<()> {
        match self.position(key) {
            Ok(index) => {
                self.0[index].1.zeroize();
                self.0[index].1 = value;
                Ok(())
            }
            Err(index) => {
                if self.0.len() >= MAX_INT_RECORDS {
                    return Err(Error::Quota);
                }
                if self.0.len() == self.0.capacity() {
                    let additional = INT_STORE_GROWTH.min(MAX_INT_RECORDS - self.0.len());
                    self.0
                        .try_reserve_exact(additional)
                        .map_err(|_| Error::Quota)?;
                }
                self.0.insert(index, (key, value));
                Ok(())
            }
        }
    }

    pub(super) fn len(&self) -> usize {
        self.0.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(super) fn iter(&self) -> core::slice::Iter<'_, (i32, i32)> {
        self.0.iter()
    }

    pub(super) fn values_mut(&mut self) -> impl Iterator<Item = &mut i32> {
        self.0.iter_mut().map(|(_, value)| value)
    }
}

#[cfg(test)]
impl core::ops::Index<&i32> for IntStore {
    type Output = i32;

    fn index(&self, key: &i32) -> &Self::Output {
        self.get(key).expect("missing integer record")
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub(super) struct BlobStore(pub(super) Vec<(i32, Vec<u8>)>);

impl Drop for BlobStore {
    fn drop(&mut self) {
        for value in self.values_mut() {
            value.zeroize();
        }
    }
}

impl BlobStore {
    pub(super) fn new() -> Self {
        Self(Vec::new())
    }

    pub(super) fn try_clone_with(
        &self,
        context: &mut crate::fallible_clone::CloneContext,
    ) -> Result<Self> {
        let mut values = Self::new();
        context.reserve_exact(&mut values.0, self.0.len())?;
        for (key, value) in &self.0 {
            values.0.push((*key, context.clone_vec(value)?));
        }
        Ok(values)
    }

    fn position(&self, key: i32) -> core::result::Result<usize, usize> {
        self.0
            .binary_search_by_key(&key, |(candidate, _)| *candidate)
    }

    pub(super) fn get(&self, key: &i32) -> Option<&Vec<u8>> {
        self.position(*key).ok().map(|index| &self.0[index].1)
    }

    pub(super) fn contains_key(&self, key: &i32) -> bool {
        self.position(*key).is_ok()
    }

    pub(super) fn insert(&mut self, key: i32, mut value: Vec<u8>) -> Result<()> {
        match self.position(key) {
            Ok(index) => {
                self.0[index].1.zeroize();
                self.0[index].1 = value;
                Ok(())
            }
            Err(index) => {
                if self.0.len() >= MAX_BLOB_RECORDS {
                    value.zeroize();
                    return Err(Error::Quota);
                }
                if self.0.len() == self.0.capacity() {
                    let additional = BLOB_STORE_GROWTH.min(MAX_BLOB_RECORDS - self.0.len());
                    if self.0.try_reserve_exact(additional).is_err() {
                        value.zeroize();
                        return Err(Error::Quota);
                    }
                }
                self.0.insert(index, (key, value));
                Ok(())
            }
        }
    }

    pub(super) fn remove(&mut self, key: &i32) -> Option<Vec<u8>> {
        self.position(*key).ok().map(|index| self.0.remove(index).1)
    }

    pub(super) fn len(&self) -> usize {
        self.0.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(super) fn iter(&self) -> core::slice::Iter<'_, (i32, Vec<u8>)> {
        self.0.iter()
    }

    pub(super) fn values(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.0.iter().map(|(_, value)| value)
    }

    pub(super) fn values_mut(&mut self) -> impl Iterator<Item = &mut Vec<u8>> {
        self.0.iter_mut().map(|(_, value)| value)
    }
}

#[cfg(test)]
impl core::ops::Index<&i32> for BlobStore {
    type Output = Vec<u8>;

    fn index(&self, key: &i32) -> &Self::Output {
        self.get(key).expect("missing byte record")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Instances(pub(super) Vec<(String, Rc<str>)>);

impl Instances {
    pub(super) fn new() -> Self {
        Self(Vec::new())
    }

    pub(super) fn try_clone_with(
        &self,
        context: &mut crate::fallible_clone::CloneContext,
    ) -> Result<Self> {
        let mut instances = Vec::new();
        context.reserve_exact(&mut instances, self.0.len())?;
        for (aid, assembly) in &self.0 {
            instances.push((context.clone_string(aid)?, Rc::clone(assembly)));
        }
        Ok(Self(instances))
    }

    fn position(&self, aid: &str) -> core::result::Result<usize, usize> {
        self.0
            .binary_search_by(|(candidate, _)| candidate.as_str().cmp(aid))
    }

    pub(super) fn reserve_entry(&mut self) -> Result<()> {
        if self.0.len() >= MAX_INSTANCES_PER_DOMAIN as usize {
            return Err(Error::Quota);
        }
        if self.0.len() == self.0.capacity() {
            self.0.try_reserve_exact(1).map_err(|_| Error::Quota)?;
        }
        Ok(())
    }

    pub(super) fn insert(&mut self, aid: String, assembly: Rc<str>) -> Result<()> {
        match self.position(&aid) {
            Ok(_) => Err(Error::Busy),
            Err(index) => {
                self.reserve_entry()?;
                self.0.insert(index, (aid, assembly));
                Ok(())
            }
        }
    }

    pub(super) fn get(&self, aid: &str) -> Option<&Rc<str>> {
        self.position(aid).ok().map(|index| &self.0[index].1)
    }

    #[cfg(test)]
    pub(super) fn get_mut(&mut self, aid: &str) -> Option<&mut Rc<str>> {
        self.position(aid).ok().map(|index| &mut self.0[index].1)
    }

    pub(super) fn contains_key(&self, aid: &str) -> bool {
        self.position(aid).is_ok()
    }

    pub(super) fn remove(&mut self, aid: &str) -> Option<Rc<str>> {
        self.position(aid).ok().map(|index| self.0.remove(index).1)
    }

    pub(super) fn len(&self) -> usize {
        self.0.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(super) fn iter(&self) -> core::slice::Iter<'_, (String, Rc<str>)> {
        self.0.iter()
    }

    pub(super) fn keys(&self) -> impl Iterator<Item = &String> {
        self.0.iter().map(|(aid, _)| aid)
    }

    pub(super) fn values(&self) -> impl Iterator<Item = &Rc<str>> {
        self.0.iter().map(|(_, assembly)| assembly)
    }

    pub(super) fn values_mut(&mut self) -> impl Iterator<Item = &mut Rc<str>> {
        self.0.iter_mut().map(|(_, assembly)| assembly)
    }
}

#[cfg(test)]
impl core::ops::Index<&str> for Instances {
    type Output = Rc<str>;

    fn index(&self, aid: &str) -> &Self::Output {
        self.get(aid).expect("missing installed instance")
    }
}
