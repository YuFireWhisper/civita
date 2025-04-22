use std::{
    borrow::Borrow,
    collections::{hash_map, HashMap},
    hash::Hash,
};

#[derive(Clone)]
#[derive(Debug)]
#[derive(PartialEq, Eq)]
pub struct IndexedMap<K, V>
where
    K: Eq + Hash,
{
    entries: HashMap<K, V>,
    index_to_key: HashMap<u16, K>,
    key_to_index: HashMap<K, u16>,
}

pub struct IndexedIter<'a, K, V>
where
    K: Eq + Hash + Clone + Ord,
{
    map: &'a IndexedMap<K, V>,
    index_iter: hash_map::Iter<'a, u16, K>,
}

pub struct IndexedValueIter<'a, K, V>
where
    K: Eq + Hash + Clone + Ord,
{
    map: &'a IndexedMap<K, V>,
    index_iter: hash_map::Iter<'a, u16, K>,
}

pub struct IndexedValueIterMut<'a, K, V>
where
    K: Eq + Hash + Clone + Ord,
{
    map: &'a mut IndexedMap<K, V>,
    indices_and_keys: Vec<(u16, K)>,
    current: usize,
    _marker: std::marker::PhantomData<&'a mut ()>,
}

impl<K, V> IndexedMap<K, V>
where
    K: Eq + Hash + Clone + Ord,
{
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: u16) -> Self {
        let entries = HashMap::with_capacity(capacity as usize);
        let index_to_key = HashMap::with_capacity(capacity as usize);
        let key_to_index = HashMap::with_capacity(capacity as usize);

        Self {
            entries,
            index_to_key,
            key_to_index,
        }
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let old_value = self.entries.insert(key, value);
        if old_value.is_none() {
            self.reorder_index();
        }
        old_value
    }

    pub fn reorder_index(&mut self) {
        self.index_to_key.clear();
        self.key_to_index.clear();

        let mut keys: Vec<K> = self.entries.keys().cloned().collect();
        keys.sort_unstable();

        for (index, key) in keys.iter().enumerate() {
            let index = (index + 1) as u16; // 1-based index
            self.index_to_key.insert(index, key.clone());
            self.key_to_index.insert(key.clone(), index);
        }
    }

    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        let old_value = self.entries.remove(key);

        if old_value.is_some() {
            if let Some(index) = self.key_to_index.remove(key) {
                self.index_to_key.remove(&index);
            }
        }

        old_value
    }

    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.entries.get(key)
    }

    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.entries.get_mut(key)
    }

    pub fn get_by_index(&self, index: &u16) -> Option<&V> {
        self.index_to_key
            .get(index)
            .and_then(|key| self.entries.get(key))
    }

    pub fn get_mut_by_index(&mut self, index: &u16) -> Option<&mut V> {
        self.index_to_key
            .get(index)
            .and_then(|key| self.entries.get_mut(key))
    }

    pub fn get_key(&self, index: &u16) -> Option<&K> {
        self.index_to_key.get(index)
    }

    pub fn get_index(&self, key: &K) -> Option<u16> {
        self.key_to_index.get(key).cloned()
    }

    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.entries.contains_key(key)
    }

    pub fn contains_index(&self, index: &u16) -> bool {
        self.index_to_key.contains_key(index)
    }

    pub fn len(&self) -> u16 {
        self.entries.len() as u16
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.entries.keys()
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.entries.values()
    }

    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut V> {
        self.entries.values_mut()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&K, &mut V)> {
        self.entries.iter_mut()
    }

    pub fn indices(&self) -> impl Iterator<Item = &u16> {
        self.index_to_key.keys()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.index_to_key.clear();
        self.key_to_index.clear();
    }

    pub fn iter_indexed(&self) -> IndexedIter<'_, K, V> {
        IndexedIter {
            map: self,
            index_iter: self.index_to_key.iter(),
        }
    }

    pub fn iter_indexed_values(&self) -> IndexedValueIter<'_, K, V> {
        IndexedValueIter {
            map: self,
            index_iter: self.index_to_key.iter(),
        }
    }

    pub fn iter_indexed_values_mut(&mut self) -> IndexedValueIterMut<'_, K, V> {
        let indices_and_keys: Vec<_> = self
            .index_to_key
            .iter()
            .map(|(idx, key)| (*idx, key.clone()))
            .collect();

        IndexedValueIterMut {
            map: self,
            indices_and_keys,
            current: 0,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<K, V> Default for IndexedMap<K, V>
where
    K: Eq + Hash + Clone + Ord,
{
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            index_to_key: HashMap::new(),
            key_to_index: HashMap::new(),
        }
    }
}

impl<K, V> FromIterator<(K, V)> for IndexedMap<K, V>
where
    K: Eq + Hash + Clone + Ord,
{
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut map = Self::new();
        map.extend(iter);
        map
    }
}

impl<K, V> From<IndexedMap<K, V>> for HashMap<K, V>
where
    K: Eq + Hash + Clone + Ord,
{
    fn from(indexed_map: IndexedMap<K, V>) -> Self {
        indexed_map.entries
    }
}

impl<K, V> From<HashMap<K, V>> for IndexedMap<K, V>
where
    K: Eq + Hash + Clone + Ord,
{
    fn from(entries: HashMap<K, V>) -> Self {
        let mut map = IndexedMap::new();
        map.extend(entries);
        map
    }
}

impl<'a, K, V> Iterator for IndexedIter<'a, K, V>
where
    K: Eq + Hash + Clone + Ord,
{
    type Item = (&'a u16, &'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        self.index_iter.next().map(|(index, key)| {
            let value = self
                .map
                .entries
                .get(key)
                .expect("Index-key mapping inconsistent");
            (index, key, value)
        })
    }
}

impl<'a, K, V> Iterator for IndexedValueIter<'a, K, V>
where
    K: Eq + Hash + Clone + Ord,
{
    type Item = (&'a u16, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        self.index_iter.next().map(|(index, key)| {
            let value = self
                .map
                .entries
                .get(key)
                .expect("Index-key mapping inconsistent");
            (index, value)
        })
    }
}

impl<'a, K, V> Iterator for IndexedValueIterMut<'a, K, V>
where
    K: Eq + Hash + Clone + Ord,
{
    type Item = (u16, &'a mut V);

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.indices_and_keys.len() {
            return None;
        }

        let (index, key) = &self.indices_and_keys[self.current];
        self.current += 1;

        let value = {
            let entries = &mut self.map.entries;
            entries.get_mut(key)?
        };

        let value = unsafe { std::mem::transmute::<&mut V, &'a mut V>(value) };
        Some((*index, value))
    }
}

impl<K, V> Extend<(K, V)> for IndexedMap<K, V>
where
    K: Eq + Hash + Clone + Ord,
{
    fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, iter: I) {
        let old_len = self.len();

        for (k, v) in iter {
            self.entries.insert(k.clone(), v);
        }

        if self.len() > old_len {
            self.reorder_index();
        }
    }
}

impl<K, V> IntoIterator for IndexedMap<K, V>
where
    K: Eq + Hash + Clone + Ord,
{
    type Item = (K, V);
    type IntoIter = hash_map::IntoIter<K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl<'a, K, V> IntoIterator for &'a IndexedMap<K, V>
where
    K: Eq + Hash + Clone + Ord,
{
    type Item = (&'a K, &'a V);
    type IntoIter = hash_map::Iter<'a, K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

impl<'a, K, V> IntoIterator for &'a mut IndexedMap<K, V>
where
    K: Eq + Hash + Clone + Ord,
{
    type Item = (&'a K, &'a mut V);
    type IntoIter = hash_map::IterMut<'a, K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const TEST_MAP_SIZE: usize = 3;

    fn create_test_map() -> IndexedMap<String, i32> {
        let mut map = IndexedMap::new();
        map.insert("c".to_string(), 3);
        map.insert("a".to_string(), 1);
        map.insert("b".to_string(), 2);
        map
    }

    #[test]
    fn new_creates_empty_map() {
        let map: IndexedMap<String, i32> = IndexedMap::new();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn with_capacity_creates_empty_map_with_capacity() {
        let map: IndexedMap<String, i32> = IndexedMap::with_capacity(10);
        assert!(map.is_empty());
    }

    #[test]
    fn from_iter_builds_map_correctly() {
        let items = vec![
            ("a".to_string(), 1),
            ("c".to_string(), 3),
            ("b".to_string(), 2),
        ];

        let map = IndexedMap::from_iter(items);

        assert_eq!(map.len(), 3);
        assert_eq!(map.get(&"a".to_string()), Some(&1));
        assert_eq!(map.get_index(&"a".to_string()), Some(1));
        assert_eq!(map.get_index(&"b".to_string()), Some(2));
        assert_eq!(map.get_index(&"c".to_string()), Some(3));
    }

    #[test]
    fn insert_adds_new_entry_and_reorganizes_indices() {
        let mut map = IndexedMap::new();

        map.insert("b".to_string(), 2);
        assert_eq!(map.get_index(&"b".to_string()), Some(1));

        map.insert("a".to_string(), 1);
        assert_eq!(map.get_index(&"a".to_string()), Some(1));
        assert_eq!(map.get_index(&"b".to_string()), Some(2));

        map.insert("c".to_string(), 3);
        assert_eq!(map.get_index(&"a".to_string()), Some(1));
        assert_eq!(map.get_index(&"b".to_string()), Some(2));
        assert_eq!(map.get_index(&"c".to_string()), Some(3));
    }

    #[test]
    fn insert_updates_existing_entry_without_changing_indices() {
        let mut map = create_test_map();

        let old_value = map.insert("b".to_string(), 20);

        assert_eq!(old_value, Some(2));
        assert_eq!(map.get(&"b".to_string()), Some(&20));
        assert_eq!(map.get_index(&"b".to_string()), Some(2));
    }

    #[test]
    fn remove_entry_leaves_index_gap() {
        let mut map = create_test_map();

        let removed = map.remove(&"b".to_string());

        assert_eq!(removed, Some(2));
        assert_eq!(map.len(), 2);
        assert!(map.get(&"b".to_string()).is_none());
        assert!(map.get_by_index(&2).is_none());

        assert_eq!(map.get_index(&"a".to_string()), Some(1));
        assert_eq!(map.get_index(&"c".to_string()), Some(3));
    }

    #[test]
    fn remove_nonexistent_entry_returns_none() {
        let mut map = create_test_map();

        let result = map.remove(&"d".to_string());

        assert_eq!(result, None);
        assert_eq!(map.len(), TEST_MAP_SIZE as u16);
    }

    #[test]
    fn get_returns_correct_value() {
        let map = create_test_map();

        assert_eq!(map.get(&"a".to_string()), Some(&1));
        assert_eq!(map.get(&"b".to_string()), Some(&2));
        assert_eq!(map.get(&"c".to_string()), Some(&3));
        assert_eq!(map.get(&"d".to_string()), None);
    }

    #[test]
    fn get_mut_allows_value_modification() {
        let mut map = create_test_map();

        if let Some(value) = map.get_mut(&"b".to_string()) {
            *value = 20;
        }

        assert_eq!(map.get(&"b".to_string()), Some(&20));
    }

    #[test]
    fn get_by_index_returns_correct_value() {
        let map = create_test_map();

        assert_eq!(map.get_by_index(&1), Some(&1)); // "a" at index 1
        assert_eq!(map.get_by_index(&2), Some(&2)); // "b" at index 2
        assert_eq!(map.get_by_index(&3), Some(&3)); // "c" at index 3
        assert_eq!(map.get_by_index(&4), None);
    }

    #[test]
    fn get_mut_by_index_allows_value_modification() {
        let mut map = create_test_map();

        if let Some(value) = map.get_mut_by_index(&2) {
            *value = 20;
        }

        assert_eq!(map.get(&"b".to_string()), Some(&20));
    }

    #[test]
    fn get_key_by_index_returns_correct_key() {
        let map = create_test_map();

        assert_eq!(map.get_key(&1).map(|s| s.as_str()), Some("a"));
        assert_eq!(map.get_key(&2).map(|s| s.as_str()), Some("b"));
        assert_eq!(map.get_key(&3).map(|s| s.as_str()), Some("c"));
        assert_eq!(map.get_key(&4), None);
    }

    #[test]
    fn get_index_returns_correct_index() {
        let map = create_test_map();

        assert_eq!(map.get_index(&"a".to_string()), Some(1));
        assert_eq!(map.get_index(&"b".to_string()), Some(2));
        assert_eq!(map.get_index(&"c".to_string()), Some(3));
        assert_eq!(map.get_index(&"d".to_string()), None);
    }

    #[test]
    fn contains_key_correctly_identifies_presence() {
        let map = create_test_map();

        assert!(map.contains_key(&"a".to_string()));
        assert!(map.contains_key(&"b".to_string()));
        assert!(map.contains_key(&"c".to_string()));
        assert!(!map.contains_key(&"d".to_string()));
    }

    #[test]
    fn contains_index_correctly_identifies_presence() {
        let map = create_test_map();

        assert!(map.contains_index(&1));
        assert!(map.contains_index(&2));
        assert!(map.contains_index(&3));
        assert!(!map.contains_index(&4));
    }

    #[test]
    fn reorder_indices_sorts_by_keys() {
        let mut map = IndexedMap::new();

        map.entries.insert("c".to_string(), 3);
        map.entries.insert("a".to_string(), 1);
        map.entries.insert("b".to_string(), 2);

        map.reorder_index();

        assert_eq!(map.get_index(&"a".to_string()), Some(1));
        assert_eq!(map.get_index(&"b".to_string()), Some(2));
        assert_eq!(map.get_index(&"c".to_string()), Some(3));
    }

    #[test]
    fn indices_should_start_from_1() {
        let map = create_test_map();

        let min_index = map.indices().min().unwrap();
        assert_eq!(*min_index, 1, "Index should start from 1");
    }

    #[test]
    fn len_returns_correct_count() {
        let map = create_test_map();
        assert_eq!(map.len(), TEST_MAP_SIZE as u16);

        let empty_map: IndexedMap<String, i32> = IndexedMap::new();
        assert_eq!(empty_map.len(), 0);
    }

    #[test]
    fn is_empty_returns_correct_result() {
        let map = create_test_map();
        assert!(!map.is_empty());

        let empty_map: IndexedMap<String, i32> = IndexedMap::new();
        assert!(empty_map.is_empty());
    }

    #[test]
    fn keys_returns_all_keys() {
        let map = create_test_map();

        let keys: HashSet<&str> = map.keys().map(|k| k.as_str()).collect();
        assert_eq!(keys.len(), TEST_MAP_SIZE);
        assert!(keys.contains("a"));
        assert!(keys.contains("b"));
        assert!(keys.contains("c"));
    }

    #[test]
    fn values_returns_all_values() {
        let map = create_test_map();

        let mut values: Vec<&i32> = map.values().collect();
        values.sort();

        assert_eq!(values.len(), TEST_MAP_SIZE);
        assert_eq!(values, vec![&1, &2, &3]);
    }

    #[test]
    fn values_mut_allows_modification() {
        let mut map = create_test_map();

        for value in map.values_mut() {
            *value *= 2;
        }

        assert_eq!(map.get(&"a".to_string()), Some(&2));
        assert_eq!(map.get(&"b".to_string()), Some(&4));
        assert_eq!(map.get(&"c".to_string()), Some(&6));
    }

    #[test]
    fn iter_returns_all_entries() {
        let map = create_test_map();

        let entries: HashMap<&str, &i32> = map.iter().map(|(k, v)| (k.as_str(), v)).collect();

        assert_eq!(entries.len(), TEST_MAP_SIZE);
        assert_eq!(entries.get("a"), Some(&&1));
        assert_eq!(entries.get("b"), Some(&&2));
        assert_eq!(entries.get("c"), Some(&&3));
    }

    #[test]
    fn iter_mut_allows_modification() {
        let mut map = create_test_map();

        for (_, value) in map.iter_mut() {
            *value *= 2;
        }

        assert_eq!(map.get(&"a".to_string()), Some(&2));
        assert_eq!(map.get(&"b".to_string()), Some(&4));
        assert_eq!(map.get(&"c".to_string()), Some(&6));
    }

    #[test]
    fn iter_indexed_provides_correct_triplets() {
        let map = create_test_map();

        let mut triplets = Vec::new();
        for (index, key, value) in map.iter_indexed() {
            triplets.push((index, key.clone(), *value));
        }

        triplets.sort_by_key(|(idx, _, _)| *idx);

        assert_eq!(triplets.len(), TEST_MAP_SIZE);
        assert_eq!(triplets[0], (&1, "a".to_string(), 1));
        assert_eq!(triplets[1], (&2, "b".to_string(), 2));
        assert_eq!(triplets[2], (&3, "c".to_string(), 3));
    }

    #[test]
    fn clear_removes_all_entries() {
        let mut map = create_test_map();

        map.clear();

        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
        assert!(map.indices().next().is_none());
    }

    #[test]
    fn default_creates_empty_map() {
        let map: IndexedMap<String, i32> = IndexedMap::default();

        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn extend_adds_and_updates_entries() {
        let mut map = IndexedMap::new();
        map.insert("a".to_string(), 1);

        let new_entries = vec![("b".to_string(), 2), ("c".to_string(), 3)];

        map.extend(new_entries);

        assert_eq!(map.len(), TEST_MAP_SIZE as u16);
        assert_eq!(map.get(&"a".to_string()), Some(&1));
        assert_eq!(map.get(&"b".to_string()), Some(&2));
        assert_eq!(map.get(&"c".to_string()), Some(&3));

        assert_eq!(map.get_index(&"a".to_string()), Some(1));
        assert_eq!(map.get_index(&"b".to_string()), Some(2));
        assert_eq!(map.get_index(&"c".to_string()), Some(3));
    }

    #[test]
    fn into_iter_converts_map_to_iterator() {
        let map = create_test_map();

        let entries: HashMap<String, i32> = map.into_iter().collect();

        assert_eq!(entries.len(), TEST_MAP_SIZE);
        assert_eq!(entries.get("a"), Some(&1));
        assert_eq!(entries.get("b"), Some(&2));
        assert_eq!(entries.get("c"), Some(&3));
    }

    #[test]
    fn into_iter_ref_iterates_entries() {
        let map = create_test_map();

        let entries: HashMap<&str, &i32> =
            (&map).into_iter().map(|(k, v)| (k.as_str(), v)).collect();

        assert_eq!(entries.len(), TEST_MAP_SIZE);
        assert_eq!(entries.get("a"), Some(&&1));
        assert_eq!(entries.get("b"), Some(&&2));
        assert_eq!(entries.get("c"), Some(&&3));
    }

    #[test]
    fn when_removing_entries_indices_are_not_reorganized() {
        let mut map = create_test_map();

        map.remove(&"b".to_string());

        assert_eq!(map.get_index(&"a".to_string()), Some(1));
        assert_eq!(map.get_index(&"c".to_string()), Some(3));
        assert!(!map.contains_index(&2));

        map.insert("d".to_string(), 4);

        assert_eq!(map.get_index(&"a".to_string()), Some(1));
        assert_eq!(map.get_index(&"c".to_string()), Some(2));
        assert_eq!(map.get_index(&"d".to_string()), Some(3));
    }

    #[test]
    fn indexed_map_can_be_converted_to_hashmap() {
        let map = create_test_map();

        let hash_map: HashMap<String, i32> = map.into();

        assert_eq!(hash_map.len(), TEST_MAP_SIZE);
        assert_eq!(hash_map.get("a"), Some(&1));
        assert_eq!(hash_map.get("b"), Some(&2));
        assert_eq!(hash_map.get("c"), Some(&3));
    }

    #[test]
    fn hash_map_can_be_converted_to_indexed_map() {
        let mut hash_map = HashMap::new();
        hash_map.insert("a".to_string(), 1);
        hash_map.insert("b".to_string(), 2);
        hash_map.insert("c".to_string(), 3);

        let indexed_map: IndexedMap<String, i32> = hash_map.into();

        assert_eq!(indexed_map.len(), TEST_MAP_SIZE as u16);
        assert_eq!(indexed_map.get(&"a".to_string()), Some(&1));
        assert_eq!(indexed_map.get(&"b".to_string()), Some(&2));
        assert_eq!(indexed_map.get(&"c".to_string()), Some(&3));
    }

    #[test]
    fn iter_indexed_values_provides_correct_pairs() {
        let map = create_test_map();

        let mut pairs = Vec::new();
        for (index, value) in map.iter_indexed_values() {
            pairs.push((index, *value));
        }

        pairs.sort_by_key(|(idx, _)| *idx);

        assert_eq!(pairs.len(), TEST_MAP_SIZE);
        assert_eq!(pairs[0], (&1, 1));
        assert_eq!(pairs[1], (&2, 2));
        assert_eq!(pairs[2], (&3, 3));
    }

    #[test]
    fn iter_indexed_values_mut_allows_modification() {
        let mut map = create_test_map();

        for (index, value) in map.iter_indexed_values_mut() {
            *value *= index as i32;
        }

        assert_eq!(map.get(&"a".to_string()), Some(&1));
        assert_eq!(map.get(&"b".to_string()), Some(&(2 * 2)));
        assert_eq!(map.get(&"c".to_string()), Some(&(3 * 3)));
    }
}
