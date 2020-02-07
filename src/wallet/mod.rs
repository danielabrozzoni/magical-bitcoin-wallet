use std::cell::RefCell;
use std::cmp;
use std::collections::{HashSet, VecDeque};
use std::convert::TryFrom;
use std::io::{Read, Write};
use std::time::Instant;

use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::util::bip32::{ChildNumber, DerivationPath};
use bitcoin::{Address, Network, OutPoint, Script, TxOut, Txid};

#[allow(unused_imports)]
use log::{debug, error, info, trace};

pub mod offline_stream;
pub mod utils;

use self::utils::ChunksIterator;
use crate::database::{BatchDatabase, BatchOperations};
use crate::descriptor::ExtendedDescriptor;
use crate::error::Error;
use crate::types::*;

#[cfg(any(feature = "electrum", feature = "default"))]
use electrum_client::types::*;
#[cfg(any(feature = "electrum", feature = "default"))]
use electrum_client::Client;
#[cfg(not(any(feature = "electrum", feature = "default")))]
use std::marker::PhantomData as Client;

pub struct Wallet<S: Read + Write, D: BatchDatabase> {
    descriptor: ExtendedDescriptor,
    change_descriptor: Option<ExtendedDescriptor>,
    network: Network,

    client: Option<RefCell<Client<S>>>,
    database: RefCell<D>,
    secp: Secp256k1<All>,
}

// offline actions, always available
impl<S, D> Wallet<S, D>
where
    S: Read + Write,
    D: BatchDatabase,
{
    pub fn new_offline(
        descriptor: ExtendedDescriptor,
        change_descriptor: Option<ExtendedDescriptor>,
        network: Network,
        database: D,
    ) -> Self {
        Wallet {
            descriptor,
            change_descriptor,
            network,

            client: None,
            database: RefCell::new(database),
            secp: Secp256k1::gen_new(),
        }
    }

    pub fn get_new_address(&self) -> Result<Address, Error> {
        let index = self
            .database
            .borrow_mut()
            .increment_last_index(ScriptType::External)?;
        // TODO: refill the address pool if index is close to the last cached addr

        self.descriptor
            .derive(index)?
            .address(self.network)
            .ok_or(Error::ScriptDoesntHaveAddressForm)
    }

    pub fn is_mine(&self, script: &Script) -> Result<bool, Error> {
        self.get_path(script).map(|x| x.is_some())
    }

    // Internals

    fn get_path(&self, script: &Script) -> Result<Option<(ScriptType, DerivationPath)>, Error> {
        self.database.borrow().get_path_from_script_pubkey(script)
    }
}

#[cfg(any(feature = "electrum", feature = "default"))]
impl<S, D> Wallet<S, D>
where
    S: Read + Write,
    D: BatchDatabase,
{
    pub fn new(
        descriptor: ExtendedDescriptor,
        change_descriptor: Option<ExtendedDescriptor>,
        network: Network,
        database: D,
        client: Client<S>,
    ) -> Self {
        Wallet {
            descriptor,
            change_descriptor,
            network,

            client: Some(RefCell::new(client)),
            database: RefCell::new(database),
            secp: Secp256k1::gen_new(),
        }
    }

    fn get_previous_output(&self, outpoint: &OutPoint) -> Option<TxOut> {
        // the fact that we visit addresses in a BFS fashion starting from the external addresses
        // should ensure that this query is always consistent (i.e. when we get to call this all
        // the transactions at a lower depth have already been indexed, so if an outpoint is ours
        // we are guaranteed to have it in the db).
        self.database
            .borrow()
            .get_raw_tx(&outpoint.txid)
            .unwrap()
            .map(|previous_tx| previous_tx.output[outpoint.vout as usize].clone())
    }

    fn check_tx_and_descendant(
        &self,
        txid: &Txid,
        height: Option<u32>,
        cur_script: &Script,
        change_max_deriv: &mut u32,
    ) -> Result<Vec<Script>, Error> {
        debug!(
            "check_tx_and_descendant of {}, height: {:?}, script: {}",
            txid, height, cur_script
        );
        let mut updates = self.database.borrow().begin_batch();
        let tx = match self.database.borrow().get_tx(&txid, true)? {
            // TODO: do we need the raw?
            Some(mut saved_tx) => {
                // update the height if it's different (in case of reorg)
                if saved_tx.height != height {
                    info!(
                        "updating height from {:?} to {:?} for tx {}",
                        saved_tx.height, height, txid
                    );
                    saved_tx.height = height;
                    updates.set_tx(&saved_tx)?;
                }

                debug!("already have {} in db, returning the cached version", txid);

                // unwrap since we explicitly ask for the raw_tx, if it's not present something
                // went wrong
                saved_tx.transaction.unwrap()
            }
            None => self
                .client
                .as_ref()
                .unwrap()
                .borrow_mut()
                .transaction_get(&txid)?,
        };

        let mut incoming: u64 = 0;
        let mut outgoing: u64 = 0;

        // look for our own inputs
        for (i, input) in tx.input.iter().enumerate() {
            if let Some(previous_output) = self.get_previous_output(&input.previous_output) {
                if self.is_mine(&previous_output.script_pubkey)? {
                    outgoing += previous_output.value;

                    debug!("{} input #{} is mine, removing from utxo", txid, i);
                    updates.del_utxo(&input.previous_output)?;
                }
            }
        }

        let mut to_check_later = vec![];
        for (i, output) in tx.output.iter().enumerate() {
            // this output is ours, we have a path to derive it
            if let Some((script_type, path)) = self.get_path(&output.script_pubkey)? {
                debug!("{} output #{} is mine, adding utxo", txid, i);
                updates.set_utxo(&UTXO {
                    outpoint: OutPoint::new(tx.txid(), i as u32),
                    txout: output.clone(),
                })?;
                incoming += output.value;

                if output.script_pubkey != *cur_script {
                    debug!("{} output #{} script {} was not current script, adding script to be checked later", txid, i, output.script_pubkey);
                    to_check_later.push(output.script_pubkey.clone())
                }

                // derive as many change addrs as external addresses that we've seen
                if script_type == ScriptType::Internal
                    && u32::from(path.as_ref()[0]) > *change_max_deriv
                {
                    *change_max_deriv = u32::from(path.as_ref()[0]);
                }
            }
        }

        let tx = TransactionDetails {
            txid: tx.txid(),
            transaction: Some(tx),
            received: incoming,
            sent: outgoing,
            height,
            timestamp: 0,
        };
        info!("Saving tx {}", txid);

        updates.set_tx(&tx)?;
        self.database.borrow_mut().commit_batch(updates)?;

        Ok(to_check_later)
    }

    fn check_history(
        &self,
        script_pubkey: Script,
        txs: Vec<GetHistoryRes>,
        change_max_deriv: &mut u32,
    ) -> Result<Vec<Script>, Error> {
        let mut to_check_later = Vec::new();

        debug!(
            "history of {} script {} has {} tx",
            Address::from_script(&script_pubkey, self.network).unwrap(),
            script_pubkey,
            txs.len()
        );

        for tx in txs {
            let height: Option<u32> = match tx.height {
                0 | -1 => None,
                x => u32::try_from(x).ok(),
            };

            to_check_later.extend_from_slice(&self.check_tx_and_descendant(
                &tx.tx_hash,
                height,
                &script_pubkey,
                change_max_deriv,
            )?);
        }

        Ok(to_check_later)
    }

    pub fn sync(
        &self,
        max_address: Option<u32>,
        batch_query_size: Option<usize>,
    ) -> Result<(), Error> {
        debug!("begin sync...");
        // TODO: consider taking an RwLock as writere here to prevent other "read-only" calls to
        // break because the db is in an inconsistent state

        let max_address = if self.descriptor.is_fixed() {
            0
        } else {
            max_address.unwrap_or(100)
        };

        let batch_query_size = batch_query_size.unwrap_or(20);
        let stop_gap = batch_query_size;

        let path = DerivationPath::from(vec![ChildNumber::Normal { index: max_address }]);
        let last_addr = self
            .database
            .borrow()
            .get_script_pubkey_from_path(ScriptType::External, &path)?;

        // cache a few of our addresses
        if last_addr.is_none() {
            let mut address_batch = self.database.borrow().begin_batch();
            let start = Instant::now();

            for i in 0..=max_address {
                let derived = self.descriptor.derive(i).unwrap();
                let full_path = DerivationPath::from(vec![ChildNumber::Normal { index: i }]);

                address_batch.set_script_pubkey(
                    &derived.script_pubkey(),
                    ScriptType::External,
                    &full_path,
                )?;
            }
            if self.change_descriptor.is_some() {
                for i in 0..=max_address {
                    let derived = self.change_descriptor.as_ref().unwrap().derive(i).unwrap();
                    let full_path = DerivationPath::from(vec![ChildNumber::Normal { index: i }]);

                    address_batch.set_script_pubkey(
                        &derived.script_pubkey(),
                        ScriptType::Internal,
                        &full_path,
                    )?;
                }
            }

            info!(
                "derivation of {} addresses, took {} ms",
                max_address,
                start.elapsed().as_millis()
            );
            self.database.borrow_mut().commit_batch(address_batch)?;
        }

        // check unconfirmed tx, delete so they are retrieved later
        let mut del_batch = self.database.borrow().begin_batch();
        for tx in self.database.borrow().iter_txs(false)? {
            if tx.height.is_none() {
                del_batch.del_tx(&tx.txid, false)?;
            }
        }
        self.database.borrow_mut().commit_batch(del_batch)?;

        // maximum derivation index for a change address that we've seen during sync
        let mut change_max_deriv = 0;

        let mut already_checked: HashSet<Script> = HashSet::new();
        let mut to_check_later = VecDeque::with_capacity(batch_query_size);

        // insert the first chunk
        let mut iter_scriptpubkeys = self
            .database
            .borrow()
            .iter_script_pubkeys(Some(ScriptType::External))?
            .into_iter();
        let chunk: Vec<Script> = iter_scriptpubkeys.by_ref().take(batch_query_size).collect();
        for item in chunk.into_iter().rev() {
            to_check_later.push_front(item);
        }

        let mut iterating_external = true;
        let mut index = 0;
        let mut last_found = 0;
        while !to_check_later.is_empty() {
            trace!("to_check_later size {}", to_check_later.len());

            let until = cmp::min(to_check_later.len(), batch_query_size);
            let chunk: Vec<Script> = to_check_later.drain(..until).collect();
            let call_result = self
                .client
                .as_ref()
                .unwrap()
                .borrow_mut()
                .batch_script_get_history(chunk.iter().collect())?; // TODO: fix electrum client

            for (script, history) in chunk.into_iter().zip(call_result.into_iter()) {
                trace!("received history for {:?}, size {}", script, history.len());

                if !history.is_empty() {
                    last_found = index;

                    let mut check_later_scripts = self
                        .check_history(script, history, &mut change_max_deriv)?
                        .into_iter()
                        .filter(|x| already_checked.insert(x.clone()))
                        .collect();
                    to_check_later.append(&mut check_later_scripts);
                }

                index += 1;
            }

            match iterating_external {
                true if index - last_found >= stop_gap => iterating_external = false,
                true => {
                    trace!("pushing one more batch from `iter_scriptpubkeys`. index = {}, last_found = {}, stop_gap = {}", index, last_found, stop_gap);

                    let chunk: Vec<Script> =
                        iter_scriptpubkeys.by_ref().take(batch_query_size).collect();
                    for item in chunk.into_iter().rev() {
                        to_check_later.push_front(item);
                    }
                }
                _ => {}
            }
        }

        // check utxo
        // TODO: try to minimize network requests and re-use scripts if possible
        let mut batch = self.database.borrow().begin_batch();
        for chunk in ChunksIterator::new(
            self.database.borrow().iter_utxos()?.into_iter(),
            batch_query_size,
        ) {
            let scripts: Vec<_> = chunk.iter().map(|u| &u.txout.script_pubkey).collect();
            let call_result = self
                .client
                .as_ref()
                .unwrap()
                .borrow_mut()
                .batch_script_list_unspent(scripts)?;

            // check which utxos are actually still unspent
            for (utxo, list_unspent) in chunk.into_iter().zip(call_result.iter()) {
                debug!(
                    "outpoint {:?} is unspent for me, list unspent is {:?}",
                    utxo.outpoint, list_unspent
                );

                let mut spent = true;
                for unspent in list_unspent {
                    let res_outpoint = OutPoint::new(unspent.tx_hash, unspent.tx_pos as u32);
                    if utxo.outpoint == res_outpoint {
                        spent = false;
                        break;
                    }
                }
                if spent {
                    info!("{} not anymore unspent, removing", utxo.outpoint);
                    batch.del_utxo(&utxo.outpoint)?;
                }
            }
        }

        let current_ext = self
            .database
            .borrow()
            .get_last_index(ScriptType::External)?
            .unwrap_or(0);
        let first_ext_new = last_found as u32 + 1;
        if first_ext_new > current_ext {
            info!("Setting external index to {}", first_ext_new);
            self.database
                .borrow_mut()
                .set_last_index(ScriptType::External, first_ext_new)?;
        }

        let current_int = self
            .database
            .borrow()
            .get_last_index(ScriptType::Internal)?
            .unwrap_or(0);
        let first_int_new = change_max_deriv + 1;
        if first_int_new > current_int {
            info!("Setting internal index to {}", first_int_new);
            self.database
                .borrow_mut()
                .set_last_index(ScriptType::Internal, first_int_new)?;
        }

        self.database.borrow_mut().commit_batch(batch)?;

        Ok(())
    }

    pub fn list_unspent(&self) -> Result<Vec<UTXO>, Error> {
        self.database.borrow().iter_utxos()
    }

    pub fn get_balance(&self) -> Result<u64, Error> {
        Ok(self
            .list_unspent()?
            .iter()
            .fold(0, |sum, i| sum + i.txout.value))
    }
}
