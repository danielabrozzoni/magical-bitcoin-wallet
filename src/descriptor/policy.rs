use std::collections::{BTreeMap, HashSet};

use serde::Serialize;

use bitcoin::hashes::*;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::bip32::Fingerprint;
use bitcoin::PublicKey;

use miniscript::{Descriptor, Satisfier, Miniscript, Terminal};

#[allow(unused_imports)]
use log::{debug, error, info, trace};

use crate::descriptor::{Key, MiniscriptExtractPolicy};
use crate::psbt::PSBTSatisfier;

#[derive(Debug, Clone, Default, Serialize)]
pub struct PKOrF {
    #[serde(skip_serializing_if = "Option::is_none")]
    pubkey: Option<PublicKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pubkey_hash: Option<hash160::Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint: Option<Fingerprint>,
}

impl PKOrF {
    fn from_key(k: &Box<dyn Key>) -> Self {
        let secp = Secp256k1::gen_new();

        let pubkey = k.as_public_key(&secp, None).unwrap();
        if let Some(fing) = k.fingerprint(&secp) {
            PKOrF {
                fingerprint: Some(fing),
                ..Default::default()
            }
        } else {
            PKOrF {
                pubkey: Some(pubkey),
                ..Default::default()
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "UPPERCASE")]
pub enum SatisfiableItem {
    // Leaves
    Signature(PKOrF),
    SignatureKey(PKOrF),
    SHA256Preimage {
        hash: sha256::Hash,
    },
    HASH256Preimage {
        hash: sha256d::Hash,
    },
    RIPEMD160Preimage {
        hash: ripemd160::Hash,
    },
    HASH160Preimage {
        hash: hash160::Hash,
    },
    AbsoluteTimelock {
        value: u32,
    },
    RelativeTimelock {
        value: u32,
    },

    // Complex item
    Thresh {
        items: Vec<Policy>,
        threshold: usize,
    },
    Multisig {
        keys: Vec<PKOrF>,
        threshold: usize,
    },
}

impl SatisfiableItem {
    pub fn is_leaf(&self) -> bool {
        match self {
            SatisfiableItem::Thresh {
                items: _,
                threshold: _,
            } => false,
            _ => true,
        }
    }

    fn satisfy(&mut self, satisfier: &PSBTSatisfier, desc_node: &Terminal<PublicKey>) -> Satisfaction {
        match (self, desc_node) {
            // "unwrap" the identity nodes
            (ref mut item, Terminal::Alt(inner)) |
            (ref mut item, Terminal::Swap(inner)) |
            (ref mut item, Terminal::Check(inner)) |
            (ref mut item, Terminal::DupIf(inner) )|
            (ref mut item, Terminal::Verify(inner) )|
            (ref mut item, Terminal::NonZero(inner) )|
            (ref mut item, Terminal::ZeroNotEqual(inner) )=> item.satisfy(satisfier, &inner.node),

            (SatisfiableItem::Signature(pk_or_f), Terminal::Pk(pk)) => satisfier.lookup_sig(pk).is_some().into(),
            (SatisfiableItem::SignatureKey(pkh_or_f), Terminal::PkH(hash)) => satisfier.lookup_pkh_sig(hash).is_some().into(),
            // TODO: support hash preimages in psbts
            (SatisfiableItem::SHA256Preimage{..}, _) | (SatisfiableItem::HASH256Preimage{..}, _) | (SatisfiableItem::RIPEMD160Preimage{..}, _) | (SatisfiableItem::HASH160Preimage{..}, _) => Satisfaction::None,
            // timelocks are always "complete"
            (SatisfiableItem::AbsoluteTimelock { value }, _) => Satisfaction::Complete{condition: PathRequirements {
                csv: None,
                timelock: Some(*value),
            }},
            (SatisfiableItem::RelativeTimelock { value }, _) => Satisfaction::Complete{condition: PathRequirements {
                csv: Some(*value),
                timelock: None,
            }},
            // TODO: multisig
            // Thresh
            (SatisfiableItem::Thresh{items, ..}, Terminal::AndV(a, b)) | (SatisfiableItem::Thresh{items, ..}, Terminal::AndB(a, b)) => {
                items[0].satisfy(satisfier, &a.node);
                items[1].satisfy(satisfier, &b.node);

                let completed: HashSet<_> = items
                    .iter()
                    .enumerate()
                    .filter(|(_, x)| match x.satisfaction {
                        Satisfaction::Complete { .. } => true,
                        _ => false,
                    })
                    .map(|(k, _)| k)
                    .collect();
                let path_req = items
                    .iter()
                    .filter_map(|x| match x.contribution {
                        Satisfaction::Complete { condition } | Satisfaction::Partial { condition, .. } => Some(condition),
                        _ => None,
                    })
                    .fold(PathRequirements::default(), |mut acc, x| {
                        acc.merge(&x).unwrap();
                        acc
                    });

                if completed.len() >= 2 {
                    Satisfaction::Complete {
                        condition: path_req,
                    }
                } else {
                    Satisfaction::from_items_threshold(completed, 2, path_req)
                }
            }
            _ => Satisfaction::None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "UPPERCASE")]
pub enum Satisfaction {
    Complete {
        #[serde(skip_serializing_if = "PathRequirements::is_null")]
        condition: PathRequirements,
    },
    Partial {
        m: usize,
        n: usize,
        completed: HashSet<usize>,
        #[serde(skip_serializing_if = "PathRequirements::is_null")]
        condition: PathRequirements,
    },
    None,
}

impl Satisfaction {
    fn from_items_threshold(items: HashSet<usize>, threshold: usize, condition: PathRequirements) -> Satisfaction {
        Satisfaction::Partial {
            m: items.len(),
            n: threshold,
            completed: items,
            condition,
        }
    }

    fn merge_partial(&mut self, other: &Satisfaction) {
        if let Satisfaction::Partial { mut m, mut n, mut completed, mut condition } = self {
        }
    }
}

/*impl std::ops::AddAssign<&Satisfaction> for Satisfaction {
    fn add_assign(&mut self, other: &Satisfaction) {
        if let Satisfaction::Complete { mut condition } = self {
            match other {
                Satisfaction::Complete { condition: other_cond } | Satisfaction::Partial { condition: other_cond, .. } => condition.merge(other_cond).unwrap(),
                _ => {}
            }
        } else if let Satisfaction::Partial { mut condition, .. } = self {
            match other {
                Satisfaction::Complete { condition: other_cond } | Satisfaction::Partial { condition: other_cond, .. } => condition.merge(other_cond).unwrap(),
                _ => {}
            }
        } else if let Satisfaction::None = self {
            *self = other.clone()
        }

        match (&self, other) {
            // complete-complete
            (
                Satisfaction::Complete { .. },
                Satisfaction::Complete { condition: b },
            ) => {
                self.condition.merge(&b).unwrap();
            }
            // complete-<any>
            (Satisfaction::Complete { condition }, _) => Satisfaction::Complete {
                condition: *condition,
            },
            (_, Satisfaction::Complete { condition }) => Satisfaction::Complete {
                condition: *condition,
            },

            // none-<any>
            (Satisfaction::None, any) => any.clone(),
            (any, Satisfaction::None) => any.clone(),

            // partial-partial
            (
                Satisfaction::Partial {
                    m: _,
                    n: a_n,
                    completed: a_items,
                },
                Satisfaction::Partial {
                    m: _,
                    n: _,
                    completed: b_items,
                },
            ) => {
                let union: HashSet<_> = a_items.union(&b_items).cloned().collect();
                Satisfaction::Partial {
                    m: union.len(),
                    n: *a_n,
                    completed: union,
                }
            }

        }
    }
} */

impl From<bool> for Satisfaction {
    fn from(other: bool) -> Self {
        if other {
            Satisfaction::Complete{condition: Default::default()}
        } else {
            Satisfaction::None
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Policy {
    #[serde(flatten)]
    item: SatisfiableItem,
    satisfaction: Satisfaction,
    contribution: Satisfaction,
}

#[derive(Debug, Default, Eq, PartialEq, Clone, Copy, Serialize)]
pub struct PathRequirements {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csv: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timelock: Option<u32>,
}

impl PathRequirements {
    pub fn merge(&mut self, other: &Self) -> Result<(), PolicyError> {
        if other.is_null() {
            return Ok(());
        }

        match (self.csv, other.csv) {
            (Some(old), Some(new)) if old != new => Err(PolicyError::DifferentCSV(old, new)),
            _ => {
                self.csv = self.csv.or(other.csv);
                Ok(())
            }
        }?;

        match (self.timelock, other.timelock) {
            // TODO: we could actually set the timelock to the highest of the two, but we would
            // have to first check that they are both in the same "unit" (blocks vs time)
            (Some(old), Some(new)) if old != new => Err(PolicyError::DifferentTimelock(old, new)),
            _ => {
                self.timelock = self.timelock.or(other.timelock);
                Ok(())
            }
        }?;

        Ok(())
    }

    pub fn is_null(&self) -> bool {
        self.csv.is_none() && self.timelock.is_none()
    }
}

#[derive(Debug)]
pub enum PolicyError {
    NotEnoughItemsSelected(usize),
    TooManyItemsSelected(usize),
    IndexOutOfRange(usize, usize),
    DifferentCSV(u32, u32),
    DifferentTimelock(u32, u32),
}

impl Policy {
    pub fn new(item: SatisfiableItem) -> Self {
        Policy {
            item,
            satisfaction: Satisfaction::None,
            contribution: Satisfaction::None,
        }
    }

    pub fn make_and(a: Option<Policy>, b: Option<Policy>) -> Option<Policy> {
        match (a, b) {
            (None, None) => None,
            (Some(x), None) | (None, Some(x)) => Some(x),
            (Some(a), Some(b)) => Self::make_thresh(vec![a, b], 2),
        }
    }

    pub fn make_or(a: Option<Policy>, b: Option<Policy>) -> Option<Policy> {
        match (a, b) {
            (None, None) => None,
            (Some(x), None) | (None, Some(x)) => Some(x),
            (Some(a), Some(b)) => Self::make_thresh(vec![a, b], 1),
        }
    }

    pub fn make_thresh(items: Vec<Policy>, threshold: usize) -> Option<Policy> {
        if threshold == 0 {
            return None;
        }

        let completed: HashSet<_> = items
            .iter()
            .enumerate()
            .filter(|(_, x)| match x.contribution {
                Satisfaction::Complete { .. } => true,
                _ => false,
            })
            .map(|(k, _)| k)
            .collect();
        let path_req = items
            .iter()
            .filter_map(|x| match x.contribution {
                Satisfaction::Complete { condition } | Satisfaction::Partial { condition, .. } => Some(condition),
                _ => None,
            })
            .fold(PathRequirements::default(), |mut acc, x| {
                acc.merge(&x).unwrap();
                acc
            });

        let mut policy: Policy = SatisfiableItem::Thresh { items, threshold }.into();
        if completed.len() >= threshold {
            policy.contribution = Satisfaction::Complete {
                condition: path_req,
            };
        } else {
            policy.contribution = Satisfaction::from_items_threshold(completed, threshold, path_req);
        }

        Some(policy)
    }

    fn make_multisig(keys: Vec<Option<&Box<dyn Key>>>, threshold: usize) -> Option<Policy> {
        let parsed_keys = keys.iter().map(|k| PKOrF::from_key(k.unwrap())).collect();
        let mut policy: Policy = SatisfiableItem::Multisig {
            keys: parsed_keys,
            threshold,
        }
        .into();
        let our_keys = keys
            .iter()
            .enumerate()
            .filter(|(_, x)| x.is_some() && x.unwrap().has_secret())
            .map(|(k, _)| k)
            .collect();
        policy.contribution = Satisfaction::from_items_threshold(our_keys, threshold, PathRequirements::default());

        Some(policy)
    }

    pub fn satisfy(&mut self, satisfier: &PSBTSatisfier, desc_node: &Terminal<PublicKey>) {
        self.satisfaction = self.item.satisfy(satisfier, desc_node);
        self.contribution += &self.satisfaction;
    }

    pub fn requires_path(&self) -> bool {
        self.get_requirements(&vec![]).is_err()
    }

    pub fn get_requirements(
        &self,
        path: &Vec<Vec<usize>>,
    ) -> Result<PathRequirements, PolicyError> {
        self.recursive_get_requirements(path, 0)
    }

    fn recursive_get_requirements(
        &self,
        path: &Vec<Vec<usize>>,
        index: usize,
    ) -> Result<PathRequirements, PolicyError> {
        // if items.len() == threshold, selected can be omitted and we take all of them by default
        let default = match &self.item {
            SatisfiableItem::Thresh { items, threshold } if items.len() == *threshold => {
                (0..*threshold).into_iter().collect()
            }
            _ => vec![],
        };
        let selected = match path.get(index) {
            _ if !default.is_empty() => &default,
            Some(arr) => arr,
            _ => &default,
        };

        match &self.item {
            SatisfiableItem::Thresh { items, threshold } => {
                let mapped_req = items
                    .iter()
                    .map(|i| i.recursive_get_requirements(path, index + 1))
                    .collect::<Result<Vec<_>, _>>()?;

                // if all the requirements are null we don't care about `selected` because there
                // are no requirements
                if mapped_req.iter().all(PathRequirements::is_null) {
                    return Ok(PathRequirements::default());
                }

                // if we have something, make sure we have enough items. note that the user can set
                // an empty value for this step in case of n-of-n, because `selected` is set to all
                // the elements above
                if selected.len() < *threshold {
                    return Err(PolicyError::NotEnoughItemsSelected(index));
                }

                // check the selected items, see if there are conflicting requirements
                let mut requirements = PathRequirements::default();
                for item_index in selected {
                    requirements.merge(
                        mapped_req
                            .get(*item_index)
                            .ok_or(PolicyError::IndexOutOfRange(*item_index, index))?,
                    )?;
                }

                Ok(requirements)
            }
            _ if !selected.is_empty() => Err(PolicyError::TooManyItemsSelected(index)),
            SatisfiableItem::AbsoluteTimelock { value } => Ok(PathRequirements {
                csv: None,
                timelock: Some(*value),
            }),
            SatisfiableItem::RelativeTimelock { value } => Ok(PathRequirements {
                csv: Some(*value),
                timelock: None,
            }),
            _ => Ok(PathRequirements::default()),
        }
    }
}

impl From<SatisfiableItem> for Policy {
    fn from(other: SatisfiableItem) -> Self {
        Self::new(other)
    }
}

fn signature_from_string(key: Option<&Box<dyn Key>>) -> Option<Policy> {
    key.map(|k| {
        let mut policy: Policy = SatisfiableItem::Signature(PKOrF::from_key(k)).into();
        policy.contribution = if k.has_secret() {
            Satisfaction::Complete {
                condition: Default::default(),
            }
        } else {
            Satisfaction::None
        };

        policy
    })
}

fn signature_key_from_string(key: Option<&Box<dyn Key>>) -> Option<Policy> {
    let secp = Secp256k1::gen_new();

    key.map(|k| {
        let pubkey = k.as_public_key(&secp, None).unwrap();
        let mut policy: Policy = if let Some(fing) = k.fingerprint(&secp) {
            SatisfiableItem::SignatureKey(PKOrF {
                fingerprint: Some(fing),
                ..Default::default()
            })
        } else {
            SatisfiableItem::SignatureKey(PKOrF {
                pubkey_hash: Some(hash160::Hash::hash(&pubkey.to_bytes())),
                ..Default::default()
            })
        }
        .into();
        policy.contribution = if k.has_secret() {
            Satisfaction::Complete {
                condition: Default::default(),
            }
        } else {
            Satisfaction::None
        };

        policy
    })
}

impl MiniscriptExtractPolicy for Miniscript<String> {
    fn extract_policy(&self, lookup_map: &BTreeMap<String, Box<dyn Key>>) -> Option<Policy> {
        match &self.node {
            // Leaves
            Terminal::True | Terminal::False => None,
            Terminal::Pk(pubkey) => signature_from_string(lookup_map.get(pubkey)),
            Terminal::PkH(pubkey_hash) => signature_key_from_string(lookup_map.get(pubkey_hash)),
            Terminal::After(value) => Some(SatisfiableItem::AbsoluteTimelock { value: *value }.into()),
            Terminal::Older(value) => Some(SatisfiableItem::RelativeTimelock { value: *value }.into()),
            Terminal::Sha256(hash) => Some(SatisfiableItem::SHA256Preimage { hash: *hash }.into()),
            Terminal::Hash256(hash) => {
                Some(SatisfiableItem::HASH256Preimage { hash: *hash }.into())
            }
            Terminal::Ripemd160(hash) => {
                Some(SatisfiableItem::RIPEMD160Preimage { hash: *hash }.into())
            }
            Terminal::Hash160(hash) => {
                Some(SatisfiableItem::HASH160Preimage { hash: *hash }.into())
            }
            Terminal::ThreshM(k, pks) => {
                Policy::make_multisig(pks.iter().map(|s| lookup_map.get(s)).collect(), *k)
            }
            // Identities
            Terminal::Alt(inner)
            | Terminal::Swap(inner)
            | Terminal::Check(inner)
            | Terminal::DupIf(inner)
            | Terminal::Verify(inner)
            | Terminal::NonZero(inner)
            | Terminal::ZeroNotEqual(inner) => inner.extract_policy(lookup_map),
            // Complex policies
            Terminal::AndV(a, b) | Terminal::AndB(a, b) => {
                Policy::make_and(a.extract_policy(lookup_map), b.extract_policy(lookup_map))
            }
            Terminal::AndOr(x, y, z) => Policy::make_or(
                Policy::make_and(x.extract_policy(lookup_map), y.extract_policy(lookup_map)),
                z.extract_policy(lookup_map),
            ),
            Terminal::OrB(a, b)
            | Terminal::OrD(a, b)
            | Terminal::OrC(a, b)
            | Terminal::OrI(a, b) => {
                Policy::make_or(a.extract_policy(lookup_map), b.extract_policy(lookup_map))
            }
            Terminal::Thresh(k, nodes) => {
                let mut threshold = *k;
                let mapped: Vec<_> = nodes
                    .iter()
                    .filter_map(|n| n.extract_policy(lookup_map))
                    .collect();

                if mapped.len() < nodes.len() {
                    threshold = match threshold.checked_sub(nodes.len() - mapped.len()) {
                        None => return None,
                        Some(x) => x,
                    };
                }

                Policy::make_thresh(mapped, threshold)
            }
        }
    }
}

impl MiniscriptExtractPolicy for Descriptor<String> {
    fn extract_policy(&self, lookup_map: &BTreeMap<String, Box<dyn Key>>) -> Option<Policy> {
        match self {
            Descriptor::Pk(pubkey)
            | Descriptor::Pkh(pubkey)
            | Descriptor::Wpkh(pubkey)
            | Descriptor::ShWpkh(pubkey) => signature_from_string(lookup_map.get(pubkey)),
            Descriptor::Bare(inner)
            | Descriptor::Sh(inner)
            | Descriptor::Wsh(inner)
            | Descriptor::ShWsh(inner) => inner.extract_policy(lookup_map),
        }
    }
}
