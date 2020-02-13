use serde::Serialize;

use bitcoin::hashes::*;
use bitcoin::util::bip32::Fingerprint;
use bitcoin::PublicKey;

use miniscript::{Descriptor, Miniscript, Terminal};

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum SatisfiableItem {
    // Leaves
    Signature {
        pubkey: PublicKey,
    },
    SignatureKey {
        pubkey_hash: hash160::Hash,
    },
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
        height: u32,
    },
    RelativeTimelock {
        blocks: u32,
    },

    // Complex item
    Thresh {
        items: Vec<Policy>,
        threshold: usize,
    },
    Multisig {
        pubkeys: Vec<PublicKey>,
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
}

#[derive(Debug, Serialize)]
pub enum ItemSatisfier {
    Us,
    Other(Option<Fingerprint>),
    Timelock(Option<u32>), // remaining blocks. TODO: time-based timelocks
}

#[derive(Debug, Serialize)]
pub struct Policy {
    #[serde(flatten)]
    item: SatisfiableItem,
    #[serde(skip_serializing_if = "Option::is_none")]
    satisfier: Option<ItemSatisfier>,
}

#[derive(Debug, Default)]
pub struct PathRequirements {
    pub csv: Option<u32>,
    pub timelock: Option<u32>,
}

impl PathRequirements {
    pub fn merge(&mut self, other: Self) -> Result<(), PolicyError> {
        match (self.csv, other.csv) {
            (Some(old), Some(new)) if old != new => Err(PolicyError::DifferentCSV(old, new)),
            _ => {
                self.csv = self.csv.or(other.csv);
                Ok(())
            }
        }?;

        match (self.timelock, other.timelock) {
            (Some(old), Some(new)) if old != new => Err(PolicyError::DifferentTimelock(old, new)),
            _ => {
                self.timelock = self.timelock.or(other.timelock);
                Ok(())
            }
        }?;

        Ok(())
    }
}

#[derive(Debug)]
pub enum PolicyError {
    NotEnoughItemsSelected,
    TooManyItemsSelected,
    DifferentCSV(u32, u32),
    DifferentTimelock(u32, u32),
}

impl Policy {
    pub fn new(item: SatisfiableItem) -> Self {
        Policy {
            item,
            satisfier: None,
        }
    }

    pub fn make_and(a: Option<Policy>, b: Option<Policy>) -> Option<Policy> {
        match (a, b) {
            (None, None) => None,
            (Some(x), None) | (None, Some(x)) => Some(x),
            (Some(a), Some(b)) => Some(
                SatisfiableItem::Thresh {
                    items: vec![a, b],
                    threshold: 2,
                }
                .into(),
            ),
        }
    }

    pub fn make_or(a: Option<Policy>, b: Option<Policy>) -> Option<Policy> {
        match (a, b) {
            (None, None) => None,
            (Some(x), None) | (None, Some(x)) => Some(x),
            (Some(a), Some(b)) => Some(
                SatisfiableItem::Thresh {
                    items: vec![a, b],
                    threshold: 1,
                }
                .into(),
            ),
        }
    }

    pub fn make_thresh(items: Vec<Policy>, mut threshold: usize) -> Option<Policy> {
        if threshold == 0 {
            return None;
        }
        if threshold > items.len() {
            threshold = items.len();
        }

        Some(SatisfiableItem::Thresh { items, threshold }.into())
    }

    pub fn make_multisig(pubkeys: Vec<PublicKey>, threshold: usize) -> Option<Policy> {
        Some(SatisfiableItem::Multisig { pubkeys, threshold }.into())
    }

    pub fn requires_path(&self) -> bool {
        !self.item.is_leaf()
    }

    pub fn get_requirements(
        &self,
        path: &Vec<Vec<usize>>,
        index: usize,
    ) -> Result<PathRequirements, PolicyError> {
        // TODO: check that indexes are in rage

        let selected = &path[index];
        match &self.item {
            SatisfiableItem::Thresh {
                items: _,
                threshold,
            } if selected.len() < *threshold => Err(PolicyError::NotEnoughItemsSelected),
            SatisfiableItem::Thresh {
                items,
                threshold: _,
            } => {
                let mut requirements = PathRequirements::default();
                for item_index in selected {
                    requirements.merge(items[*item_index].get_requirements(path, index + 1)?)?;
                }

                Ok(requirements)
            }
            _ if selected.len() > 0 => Err(PolicyError::TooManyItemsSelected),
            SatisfiableItem::AbsoluteTimelock { height } => Ok(PathRequirements {
                csv: None,
                timelock: Some(*height),
            }),
            SatisfiableItem::RelativeTimelock { blocks } => Ok(PathRequirements {
                csv: Some(*blocks),
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

pub trait ExtractPolicy {
    fn extract_policy(&self) -> Option<Policy>;
}

impl ExtractPolicy for Miniscript<PublicKey> {
    fn extract_policy(&self) -> Option<Policy> {
        match &self.node {
            // Leaves
            Terminal::True | Terminal::False => None,
            Terminal::Pk(pubkey) => Some(SatisfiableItem::Signature { pubkey: *pubkey }.into()),
            Terminal::PkH(pubkey_hash) => Some(
                SatisfiableItem::SignatureKey {
                    pubkey_hash: *pubkey_hash,
                }
                .into(),
            ),
            Terminal::After(height) => {
                Some(SatisfiableItem::AbsoluteTimelock { height: *height }.into())
            }
            Terminal::Older(blocks) => {
                Some(SatisfiableItem::RelativeTimelock { blocks: *blocks }.into())
            }
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
            // Identities
            Terminal::Alt(inner)
            | Terminal::Swap(inner)
            | Terminal::Check(inner)
            | Terminal::DupIf(inner)
            | Terminal::Verify(inner)
            | Terminal::NonZero(inner)
            | Terminal::ZeroNotEqual(inner) => inner.extract_policy(),
            // Complex policies
            Terminal::AndV(a, b) | Terminal::AndB(a, b) => {
                Policy::make_and(a.extract_policy(), b.extract_policy())
            }
            Terminal::AndOr(x, y, z) => Policy::make_or(
                Policy::make_and(x.extract_policy(), y.extract_policy()),
                z.extract_policy(),
            ),
            Terminal::OrB(a, b)
            | Terminal::OrD(a, b)
            | Terminal::OrC(a, b)
            | Terminal::OrI(a, b) => Policy::make_or(a.extract_policy(), b.extract_policy()),
            Terminal::Thresh(k, nodes) => {
                let mut threshold = *k;
                let mapped: Vec<_> = nodes.iter().filter_map(|n| n.extract_policy()).collect();

                if mapped.len() < nodes.len() {
                    threshold = match threshold.checked_sub(nodes.len() - mapped.len()) {
                        None => return None,
                        Some(x) => x,
                    };
                }

                Policy::make_thresh(mapped, threshold)
            }
            Terminal::ThreshM(k, pks) => Policy::make_multisig(pks.clone(), *k),
        }
    }
}

impl ExtractPolicy for Descriptor<PublicKey> {
    fn extract_policy(&self) -> Option<Policy> {
        match self {
            Descriptor::Pk(pubkey)
            | Descriptor::Pkh(pubkey)
            | Descriptor::Wpkh(pubkey)
            | Descriptor::ShWpkh(pubkey) => {
                Some(SatisfiableItem::Signature { pubkey: *pubkey }.into())
            }
            Descriptor::Bare(inner)
            | Descriptor::Sh(inner)
            | Descriptor::Wsh(inner)
            | Descriptor::ShWsh(inner) => inner.extract_policy(),
        }
    }
}
