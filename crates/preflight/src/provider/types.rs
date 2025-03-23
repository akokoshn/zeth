// Copyright 2023, 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use alloy::primitives::{Address, BlockHash, BlockNumber, TxHash, PrimitiveSignature as Signature, TxKind, ChainId, Bloom, Bytes, B256, b256, U256, FixedBytes};
use alloy::network::primitives::{
    BlockResponse, BlockTransactions, HeaderResponse, TransactionResponse,
};
use alloy::eips::{eip2930::AccessList, eip7702::SignedAuthorization};
use alloy::consensus::{Transaction, BlockHeader, TxType, TypedTransaction, EMPTY_OMMER_ROOT_HASH, TxLegacy};
use alloy::network::{Ethereum, Network, TransactionBuilder, TransactionBuilderError, BuildResult, NetworkWallet};
use reth_primitives::{TransactionSigned, sign_message};
use reth_revm::primitives::bytes;
use secp256k1::{rand, Keypair, Secp256k1, SecretKey};
use std::str::FromStr;

//#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
//#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
//#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(serde::Serialize)]
#[derive(serde::Deserialize)]
#[allow(non_snake_case)]
pub struct Header {
    pub number: u64,
    pub hash: BlockHash,
    pub parentHash: BlockHash,
    pub patchLevel: u32,
	pub rollbackCounter: u32,
	pub inTransactionsRoot: BlockHash,
	pub receiptsRoot: BlockHash,
	pub childBlocksRootHash: BlockHash,
	pub shardId: u32,
    //pub transactions BlockTransactions,
	//pub transaction_hashes: []BlockHash,
	//pub child_blocks: []BlockHash,
	pub mainShardHash: BlockHash,
	pub dbTimestamp: u64,
	pub baseFee: U256,
	pub l1Number: u64,
    //pub logsBloom: Bloom,
	pub gasUsed: String,
}

impl From<Header> for reth_primitives::Header {
    fn from(value: Header) -> Self {
        let parent_hash = value.parentHash;
        let ommers_hash = value.ommers_hash();
        let beneficiary = value.beneficiary();
        let state_root = value.state_root();
        let transactions_root = value.transactions_root();
        let receipts_root = value.receipts_root();
        let logs_bloom = value.logs_bloom();
        let difficulty = BlockHeader::difficulty(&value);
        let number = value.number;
        let gas_limit = BlockHeader::gas_limit(&value);
        let gas_used = value.gas_used();
        let timestamp = 1438269988u64;//value.dbTimestamp;
        let extra_data = bytes!("ff");
        let mix_hash = BlockHeader::mix_hash(&value);
        let nonce = value.nonce();
        let base_fee_per_gas = BlockHeader::base_fee_per_gas(&value);
        let withdrawals_root = value.withdrawals_root();
        let blob_gas_used = value.blob_gas_used();
        let excess_blob_gas = value.excess_blob_gas();
        let parent_beacon_block_root = value.parent_beacon_block_root();
        let requests_root = value.requests_root();

        Self {
            parent_hash,
            ommers_hash,
            beneficiary,
            state_root,
            transactions_root,
            receipts_root,
            logs_bloom,
            difficulty,
            number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            mix_hash,
            nonce,
            base_fee_per_gas,
            withdrawals_root,
            blob_gas_used,
            excess_blob_gas,
            parent_beacon_block_root,
            requests_root,
        }
    }
}

impl BlockHeader for Header {
    fn parent_hash(&self) -> B256 {
        self.parentHash
    }

    fn ommers_hash(&self) -> B256 {
        EMPTY_OMMER_ROOT_HASH
    }

    fn beneficiary(&self) -> Address {
        Address::from_str("0x0000000000000000000000000000000000000001").unwrap()
    }

    fn state_root(&self) -> B256 {
        B256::random()
    }

    fn transactions_root(&self) -> B256 {
        self.inTransactionsRoot
    }

    fn receipts_root(&self) -> B256 {
        self.receiptsRoot
    }

    fn withdrawals_root(&self) -> Option<B256> {
        None
    }

    fn logs_bloom(&self) -> Bloom {
        Bloom::default()
    }

    fn difficulty(&self) -> U256 {
        U256::from(10)
    }

    fn number(&self) -> BlockNumber {
        self.number
    }

    fn gas_limit(&self) -> u64 {
        5000000
    }

    fn gas_used(&self) -> u64 {
        100000
    }

    fn timestamp(&self) -> u64 {
        todo!()
    }

    fn mix_hash(&self) -> FixedBytes<32> {
        FixedBytes::ZERO
    }

    fn nonce(&self) -> FixedBytes<8> {
        FixedBytes::ZERO
    }

    fn base_fee_per_gas(&self) -> Option<u64> {
        Some(0)
    }

    fn blob_gas_used(&self) -> Option<u64> {
        None
    }

    fn excess_blob_gas(&self) -> Option<u64> {
        None
    }

    fn parent_beacon_block_root(&self) -> Option<FixedBytes<32>> {
        Some(B256::random())
    }

    fn requests_root(&self) -> Option<FixedBytes<32>> {
        None
    }

    fn extra_data(&self) -> &Bytes {
        todo!()
    }
}

impl HeaderResponse for Header {
    fn hash(&self) -> BlockHash {
        self.hash
    }

    fn number(&self) -> u64 { 14 }
    fn timestamp(&self) -> u64 { 0 }
    fn extra_data(&self) -> &alloy_primitives::Bytes {
        todo!()
    }
    fn base_fee_per_gas(&self) -> std::option::Option<u64> { None }
    fn next_block_blob_fee(&self) -> std::option::Option<u128> { None }
    fn coinbase(&self) -> alloy_primitives::Address {  todo!() }
    fn gas_limit(&self) -> u64 { 10000 }
    fn mix_hash(&self) -> std::option::Option<alloy_primitives::FixedBytes<32>> { todo!() }
    fn difficulty(&self) -> alloy_primitives::Uint<256, 4> { todo!() }
}

#[derive(Clone, Debug, /*Default,*/ PartialEq, Eq, Hash)]
#[derive(serde::Serialize)]
#[derive(serde::Deserialize)]
#[allow(non_snake_case)]
pub struct NilTransaction {
    pub flags: Vec<String>,
    pub success: bool,
    pub requestId: u64,
    pub data: Bytes,
    pub blockHash: BlockHash,
    pub blockNumber: u64,
    pub from: Address,
    pub gasUsed: String,
    pub feeCredit: U256,
    pub maxPriorityFeePerGas: U256,
    pub maxFeePerGas: U256,
    pub hash: BlockHash,
    pub seqno: String,
    pub to: Address,
    pub refundTo: Address,
    pub bounceTo: Address,
    pub index: String,
    pub value: U256,
    //pub token: []TokenBalance,
    //pub chainId: u64,
    pub signature: String,
}

impl From<NilTransaction> for TxLegacy {
    fn from(value: NilTransaction) -> Self {
        let chain_id = value.chain_id();
        let nonce = value.nonce();
        let gas_price = Transaction::gas_price(&value).expect("empty gas price");
        let gas_limit = value.gas_limit();
        let to = alloy_primitives::TxKind::Call(value.to);
        let input = Bytes::copy_from_slice(value.input());
        let value = value.value;

        Self {
            chain_id: chain_id,
            nonce: nonce,
            gas_price: gas_price,
            gas_limit: gas_limit,
            to: to,
            value: value,
            input: input,
        }
    }
}

impl TryFrom<NilTransaction> for TransactionSigned
{
    type Error = alloy::rpc::types::eth::ConversionError;
    fn try_from(value: NilTransaction) -> Result<Self, Self::Error> {
        let secp = Secp256k1::new();
        // TODO value.from => key
        //let key = SecretKey::from("00014982a56a0a9fd4c4fafc55b5dd05b78bcaf6").unwrap();
        //let key_pair = Keypair::from_secret_key(&secp, &key);
        let key_pair = Keypair::new(&secp, &mut rand::thread_rng());
        let transaction = reth_primitives::Transaction::Legacy(TxLegacy::from(value));
        let signature = sign_message(B256::from_slice(&key_pair.secret_bytes()[..]), transaction.signature_hash()).unwrap();
        Ok(Self::from_transaction_and_signature(transaction, signature))
    }
}

impl Transaction for NilTransaction {
    #[inline]
    fn chain_id(&self) -> Option<ChainId> {
        Some(1)
    }

    #[inline]
    fn nonce(&self) -> u64 {
        0//TODO value.seqno
    }

    #[inline]
    fn gas_limit(&self) -> u64 {
        100000//TODO value.feeCredit
    }

    #[inline]
    fn gas_price(&self) -> Option<u128> {
        Some(0x4a817c808)
    }

    #[inline]
    fn max_fee_per_gas(&self) -> u128 {
        self.maxFeePerGas.to::<u128>()
    }

    #[inline]
    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        Some(self.maxPriorityFeePerGas.to::<u128>())
    }

    #[inline]
    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        Some(0u128)
    }

    #[inline]
    fn priority_fee_or_price(&self) -> u128 {
        0
    }

    /*fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        10
    }

    #[inline]
    fn is_dynamic_fee(&self) -> bool {
        false
    }

    #[inline]
    fn kind(&self) -> TxKind {
        todo!()
    }

    #[inline]
    fn is_create(&self) -> bool {
        false
    }*/
    fn to(&self) -> TxKind { todo!() }

    fn ty(&self) -> u8 { todo!() }

    #[inline]
    fn value(&self) -> U256 {
        self.value
    }

    #[inline]
    fn input(&self) -> &[u8] {
        &self.data
    }

    #[inline]
    fn access_list(&self) -> Option<&AccessList> {
        todo!()
    }

    #[inline]
    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        None
    }

    #[inline]
    fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
        None
    }
}

impl TransactionResponse for NilTransaction {
    type Signature = Signature;

    fn signature(&self) -> std::option::Option<<Self as TransactionResponse>::Signature> { todo!() }

    fn tx_hash(&self) -> TxHash {
        todo!()
    }

    fn block_hash(&self) -> Option<BlockHash> {
        todo!()
    }

    fn block_number(&self) -> Option<u64> {
        todo!()
    }

    fn transaction_index(&self) -> Option<u64> {
        todo!()
    }

    fn from(&self) -> alloy_primitives::Address {
        todo!()
    }

    fn gas_price(&self) -> Option<u128> {
        todo!()
    }
}

impl TransactionBuilder<NilNetwork> for alloy::rpc::types::eth::transaction::TransactionRequest {
    fn chain_id(&self) -> Option<ChainId> {
        self.chain_id
    }

    fn set_chain_id(&mut self, chain_id: ChainId) {
        self.chain_id = Some(chain_id);
    }

    fn nonce(&self) -> Option<u64> {
        self.nonce
    }

    fn set_nonce(&mut self, nonce: u64) {
        self.nonce = Some(nonce);
    }

    fn input(&self) -> Option<&Bytes> {
        self.input.input()
    }

    fn set_input<T: Into<Bytes>>(&mut self, input: T) {
        self.input.input = Some(input.into());
    }

    fn from(&self) -> Option<Address> {
        self.from
    }

    fn set_from(&mut self, from: Address) {
        self.from = Some(from);
    }

    fn kind(&self) -> Option<TxKind> {
        self.to
    }

    fn clear_kind(&mut self) {
        self.to = None;
    }

    fn set_kind(&mut self, kind: TxKind) {
        self.to = Some(kind);
    }

    fn value(&self) -> Option<U256> {
        self.value
    }

    fn set_value(&mut self, value: U256) {
        self.value = Some(value)
    }

    fn gas_price(&self) -> Option<u128> {
        self.gas_price
    }

    fn set_gas_price(&mut self, gas_price: u128) {
        self.gas_price = Some(gas_price);
    }

    fn max_fee_per_gas(&self) -> Option<u128> {
        self.max_fee_per_gas
    }

    fn set_max_fee_per_gas(&mut self, max_fee_per_gas: u128) {
        self.max_fee_per_gas = Some(max_fee_per_gas);
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.max_priority_fee_per_gas
    }

    fn set_max_priority_fee_per_gas(&mut self, max_priority_fee_per_gas: u128) {
        self.max_priority_fee_per_gas = Some(max_priority_fee_per_gas);
    }

    fn gas_limit(&self) -> Option<u64> {
        self.gas
    }

    fn set_gas_limit(&mut self, gas_limit: u64) {
        self.gas = Some(gas_limit);
    }

    fn access_list(&self) -> Option<&AccessList> {
        self.access_list.as_ref()
    }

    fn set_access_list(&mut self, access_list: AccessList) {
        self.access_list = Some(access_list);
    }

    fn complete_type(&self, ty: TxType) -> Result<(), Vec<&'static str>> {
        match ty {
            TxType::Legacy => self.complete_legacy(),
            TxType::Eip2930 => self.complete_2930(),
            TxType::Eip1559 => self.complete_1559(),
            TxType::Eip4844 => self.complete_4844(),
            TxType::Eip7702 => self.complete_7702(),
        }
    }

    fn can_submit(&self) -> bool {
        // value and data may be None. If they are, they will be set to default.
        // gas fields and nonce may be None, if they are, they will be populated
        // with default values by the RPC server
        self.from.is_some()
    }

    fn can_build(&self) -> bool {
        return true
    }

    #[doc(alias = "output_transaction_type")]
    fn output_tx_type(&self) -> TxType {
        self.preferred_type()
    }

    #[doc(alias = "output_transaction_type_checked")]
    fn output_tx_type_checked(&self) -> Option<TxType> {
        self.buildable_type()
    }

    fn prep_for_submission(&mut self) {
        self.transaction_type = Some(self.preferred_type() as u8);
        self.trim_conflicting_keys();
        self.populate_blob_hashes();
    }

    fn build_unsigned(self) -> BuildResult<TypedTransaction, NilNetwork> {
        if let Err((tx_type, missing)) = self.missing_keys() {
            return Err(TransactionBuilderError::InvalidTransactionRequest(tx_type, missing)
                .into_unbuilt(self));
        }
        Ok(self.build_typed_tx().expect("checked by missing_keys"))
    }

    async fn build<W: NetworkWallet<NilNetwork>>(
        self,
        wallet: &W,
    ) -> Result<<NilNetwork as Network>::TxEnvelope, TransactionBuilderError<NilNetwork>> {
        Ok(wallet.sign_request(self).await?)
    }
}

/// Block representation for RPC.
#[derive(serde::Serialize)]
#[derive(serde::Deserialize)]
#[derive(Clone, Debug, PartialEq, Eq)]
//#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
//#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct NilBlock<T = NilTransaction, H = Header> {
    //#[cfg_attr(feature = "serde", serde(flatten))]
    #[serde(flatten)]
    pub header: H,

    /*#[cfg_attr(
        feature = "serde",
        serde(
            default = "BlockTransactions::uncle",
            skip_serializing_if = "BlockTransactions::is_uncle"
        )
    )]*/
    pub transactions: Vec<T>,
}

impl<T: TransactionResponse, H: HeaderResponse> BlockResponse for NilBlock<T, H> {
    type Header = H;
    type Transaction = T;

    fn header(&self) -> &Self::Header {
        &self.header
    }

    fn transactions(&self) -> &BlockTransactions<T> {
        todo!()
    }

    fn transactions_mut(&mut self) -> &mut BlockTransactions<Self::Transaction> {
        todo!()
    }
   
}

#[derive(Clone, Copy, Debug)]
pub struct NilNetwork {
    _private: (),
}

impl Network for NilNetwork {
    type TxType = <Ethereum as alloy::providers::Network>::TxType;

    type TxEnvelope = <Ethereum as alloy::providers::Network>::TxEnvelope;

    type UnsignedTx = <Ethereum as alloy::providers::Network>::UnsignedTx;

    type ReceiptEnvelope = <Ethereum as alloy::providers::Network>::ReceiptEnvelope;

    type Header = Header;
    //type Header = alloy::consensus::Header;

    type TransactionRequest = alloy::rpc::types::eth::transaction::TransactionRequest;

    type TransactionResponse = NilTransaction;
    //type TransactionResponse = alloy::rpc::types::eth::Transaction;

    type ReceiptResponse = alloy::rpc::types::eth::transaction::TransactionReceipt;

    type HeaderResponse = Header;
    //type HeaderResponse = alloy::rpc::types::eth::Header;

    type BlockResponse = NilBlock;
    //type BlockResponse = alloy::rpc::types::eth::Block;
}