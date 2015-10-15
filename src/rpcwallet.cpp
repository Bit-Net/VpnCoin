// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet.h"
#include "walletdb.h"
#include "bitcoinrpc.h"
#include "init.h"
#include "base58.h"
//#include "simplecrypt.h"

#include "coincontrol.h"
#include <iostream>
#include <iterator>
#include <vector>

using namespace json_spirit;
using namespace std;
typedef char * PCHAR;

int64_t nWalletUnlockTime;
static CCriticalSection cs_nWalletUnlockTime;

int GetTransactionBlockHeight(const string& TxID);
int GetValidTransaction(const string txID, CTransaction &tx);
int  GetCoinAddrInTxOutIndex(const CTransaction& tx, string sAddr, int64_t v_nValue, int iCmpType = 0);
int  GetCoinAddrInTxOutIndex(const string txID, string sAddr, int64_t v_nValue, int iCmpType = 0);
int isValidBitNetLotteryTx(const CTransaction& tx, int iTargetType, int iFromType, int iTxHei, bool bCheckBlock);	// iType = 0 = nothing; 
int isValidBitNetLotteryTx(const string& txID, int iTargetType, int iFromType, int iTxHei, bool bCheckBlock);	// iType = 0 = nothing; 
int GetTxMsgParam(const CTransaction& tx, string& sLotteryId, int& iCardType, int& iGuessType, int64_t& iAmount, int64_t& iMiniBet, int64_t& iStartBlock, int64_t& iEndBlock, int& iKeyLen, 
    string& sGuessTxt, string& sLotteryAddr, string& sLotteryPrivKey, string& sMakerAddr, string& sLotteryLinkedTxid, string& sSignMsg);
int GetTxMsgParamS(const string& txID, string& sLotteryId, int& iCardType, int& iGuessType, int64_t& iAmount, int64_t& iMiniBet, int64_t& iStartBlock, int64_t& iEndBlock, int& iKeyLen, 
    string& sGuessTxt, string& sLotteryAddr, string& sLotteryPrivKey, string& sMakerAddr, string& sLotteryLinkedTxid, string& sSignMsg);

extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, json_spirit::Object& entry);

static void accountingDeprecationCheck()
{
    if (!GetBoolArg("-enableaccounts", false))
        throw runtime_error(
            "Accounting API is deprecated and will be removed in future.\n"
            "It can easily result in negative or odd balances if misused or misunderstood, which has happened in the field.\n"
            "If you still want to enable it, add to your config file enableaccounts=1\n");

    if (GetBoolArg("-staking", true))
        throw runtime_error("If you want to use accounting API, staking must be disabled, add to your config file staking=0\n");
}

std::string HelpRequiringPassphrase()
{
    return pwalletMain->IsCrypted()
        ? "\nrequires wallet passphrase to be set with walletpassphrase first"
        : "";
}

void EnsureWalletIsUnlocked()
{
    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
    if (fWalletUnlockStakingOnly)
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Wallet is unlocked for staking only.");
}

void WalletTxToJSON(const CWalletTx& wtx, Object& entry)
{
    int confirms = wtx.GetDepthInMainChain();
    entry.push_back(Pair("confirmations", confirms));
    if (wtx.IsCoinBase() || wtx.IsCoinStake())
        entry.push_back(Pair("generated", true));
    if (confirms > 0)
    {
        entry.push_back(Pair("blockhash", wtx.hashBlock.GetHex()));
        entry.push_back(Pair("blockindex", wtx.nIndex));
        entry.push_back(Pair("blocktime", (int64_t)(mapBlockIndex[wtx.hashBlock]->nTime)));
    }
    entry.push_back(Pair("txid", wtx.GetHash().GetHex()));
    entry.push_back(Pair("time", (int64_t)wtx.GetTxTime()));
    entry.push_back(Pair("timereceived", (int64_t)wtx.nTimeReceived));
    BOOST_FOREACH(const PAIRTYPE(string,string)& item, wtx.mapValue)
        entry.push_back(Pair(item.first, item.second));
}

string AccountFromValue(const Value& value)
{
    string strAccount = value.get_str();
    if (strAccount == "*")
        throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
    return strAccount;
}

Value getinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getinfo\n"
            "Returns an object containing various state info.");

    proxyType proxy;
    GetProxy(NET_IPV4, proxy);

    Object obj, diff;
    obj.push_back(Pair("version",       FormatFullVersion()));
    obj.push_back(Pair("protocolversion",(int)PROTOCOL_VERSION));
    obj.push_back(Pair("walletversion", pwalletMain->GetVersion()));
    obj.push_back(Pair("balance",       ValueFromAmount(pwalletMain->GetBalance())));
    obj.push_back(Pair("newmint",       ValueFromAmount(pwalletMain->GetNewMint())));
    obj.push_back(Pair("stake",         ValueFromAmount(pwalletMain->GetStake())));
    obj.push_back(Pair("blocks",        (int)nBestHeight));
    obj.push_back(Pair("timeoffset",    (int64_t)GetTimeOffset()));
    int64_t mn = pindexBest->nMoneySupply;
    if( mn >= (1000000000 * COIN) ){ mn = mn - (600000000 * COIN); }
    obj.push_back(Pair("moneysupply",   ValueFromAmount(mn)));
    obj.push_back(Pair("connections",   (int)vNodes.size()));
    obj.push_back(Pair("proxy",         (proxy.first.IsValid() ? proxy.first.ToStringIPPort() : string())));
    obj.push_back(Pair("ip",            addrSeenByPeer.ToStringIP()));

    diff.push_back(Pair("proof-of-work",  GetDifficulty()));
    diff.push_back(Pair("proof-of-stake", GetDifficulty(GetLastBlockIndex(pindexBest, true))));
    obj.push_back(Pair("difficulty",    diff));

    obj.push_back(Pair("testnet",       fTestNet));
    obj.push_back(Pair("keypoololdest", (int64_t)pwalletMain->GetOldestKeyPoolTime()));
    obj.push_back(Pair("keypoolsize",   (int)pwalletMain->GetKeyPoolSize()));
    obj.push_back(Pair("paytxfee",      ValueFromAmount(nTransactionFee)));
    obj.push_back(Pair("mininput",      ValueFromAmount(nMinimumInputValue)));
    if (pwalletMain->IsCrypted())
        obj.push_back(Pair("unlocked_until", (int64_t)nWalletUnlockTime / 1000));
    obj.push_back(Pair("errors",        GetWarnings("statusbar")));
    return obj;
}


Value getnewpubkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getnewpubkey [account]\n"
            "Returns new public key for coinbase generation.");

    // Parse the account first so we don't generate a key if there's an error
    string strAccount;
    if (params.size() > 0)
        strAccount = AccountFromValue(params[0]);

    if (!pwalletMain->IsLocked())
        pwalletMain->TopUpKeyPool();

    // Generate a new key that is added to wallet
    CPubKey newKey;
    if (!pwalletMain->GetKeyFromPool(newKey, false))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    CKeyID keyID = newKey.GetID();

    pwalletMain->SetAddressBookName(keyID, strAccount);
    vector<unsigned char> vchPubKey = newKey.Raw();

    return HexStr(vchPubKey.begin(), vchPubKey.end());
}


Value getnewaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getnewaddress [account]\n"
            "Returns a new VpnCoin address for receiving payments.  "
            "If [account] is specified, it is added to the address book "
            "so payments received with the address will be credited to [account].");

    // Parse the account first so we don't generate a key if there's an error
    string strAccount;
    if (params.size() > 0)
        strAccount = AccountFromValue(params[0]);

    if (!pwalletMain->IsLocked())
        pwalletMain->TopUpKeyPool();

    // Generate a new key that is added to wallet
    CPubKey newKey;
    if (!pwalletMain->GetKeyFromPool(newKey, false))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    CKeyID keyID = newKey.GetID();

    pwalletMain->SetAddressBookName(keyID, strAccount);

    return CBitcoinAddress(keyID).ToString();
}


CBitcoinAddress GetAccountAddress(string strAccount, bool bForceNew=false)
{
    CWalletDB walletdb(pwalletMain->strWalletFile);

    CAccount account;
    walletdb.ReadAccount(strAccount, account);

    bool bKeyUsed = false;

    // Check if the current key has been used
    if (account.vchPubKey.IsValid())
    {
        CScript scriptPubKey;
        scriptPubKey.SetDestination(account.vchPubKey.GetID());
        for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin();
             it != pwalletMain->mapWallet.end() && account.vchPubKey.IsValid();
             ++it)
        {
            const CWalletTx& wtx = (*it).second;
            BOOST_FOREACH(const CTxOut& txout, wtx.vout)
                if (txout.scriptPubKey == scriptPubKey)
                    bKeyUsed = true;
        }
    }

    // Generate a new key
    if (!account.vchPubKey.IsValid() || bForceNew || bKeyUsed)
    {
        if (!pwalletMain->GetKeyFromPool(account.vchPubKey, false))
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

        pwalletMain->SetAddressBookName(account.vchPubKey.GetID(), strAccount);
        walletdb.WriteAccount(strAccount, account);
    }

    return CBitcoinAddress(account.vchPubKey.GetID());
}

Value getaccountaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaccountaddress <account>\n"
            "Returns the current VpnCoin address for receiving payments to this account.");

    // Parse the account first so we don't generate a key if there's an error
    string strAccount = AccountFromValue(params[0]);

    Value ret;

    ret = GetAccountAddress(strAccount).ToString();

    return ret;
}



Value setaccount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "setaccount <vpncoinaddress> <account>\n"
            "Sets the account associated with the given address.");

    CBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid VpnCoin address");


    string strAccount;
    if (params.size() > 1)
        strAccount = AccountFromValue(params[1]);

    // Detect when changing the account of an address that is the 'unused current key' of another account:
    if (pwalletMain->mapAddressBook.count(address.Get()))
    {
        string strOldAccount = pwalletMain->mapAddressBook[address.Get()];
        if (address == GetAccountAddress(strOldAccount))
            GetAccountAddress(strOldAccount, true);
    }

    pwalletMain->SetAddressBookName(address.Get(), strAccount);

    return Value::null;
}


string getAccount(string sAddr)
{
	string rzt = "";
	if( sAddr.length() < 30 ){ return rzt; }

    CBitcoinAddress address( sAddr );
    if (!address.IsValid()){ return rzt; }

    string strAccount;
    map<CTxDestination, string>::iterator mi = pwalletMain->mapAddressBook.find(address.Get());
    if (mi != pwalletMain->mapAddressBook.end() && !(*mi).second.empty())
        strAccount = (*mi).second;
    return strAccount;
}

Value getaccount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaccount <vpncoinaddress>\n"
            "Returns the account associated with the given address.");

    CBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid VpnCoin address");

    string strAccount;
    map<CTxDestination, string>::iterator mi = pwalletMain->mapAddressBook.find(address.Get());
    if (mi != pwalletMain->mapAddressBook.end() && !(*mi).second.empty())
        strAccount = (*mi).second;
    return strAccount;
}


Value getaddressesbyaccount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaddressesbyaccount <account>\n"
            "Returns the list of addresses for the given account.");

    string strAccount = AccountFromValue(params[0]);

    // Find all addresses that have the given account
    Array ret;
    BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, string)& item, pwalletMain->mapAddressBook)
    {
        const CBitcoinAddress& address = item.first;
        const string& strName = item.second;
        if (strName == strAccount)
            ret.push_back(address.ToString());
    }
    return ret;
}

Value sendtoaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
        throw runtime_error(
            "sendtoaddress <vpncoinaddress> <amount> [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest 0.000001"
            + HelpRequiringPassphrase());

    CBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid VpnCoin address");

    // Amount
    int64_t nAmount = AmountFromValue(params[1]);

    // Wallet comments
    CWalletTx wtx;
    if (params.size() > 2 && params[2].type() != null_type && !params[2].get_str().empty())
        wtx.mapValue["comment"] = params[2].get_str();
    if (params.size() > 3 && params[3].type() != null_type && !params[3].get_str().empty())
        wtx.mapValue["to"]      = params[3].get_str();

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    string stxData = "";
	string strError = pwalletMain->SendMoneyToDestination(address.Get(), nAmount, wtx, stxData);
    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    return wtx.GetHash().GetHex();
}

Value listaddressgroupings(const Array& params, bool fHelp)
{
    if (fHelp)
        throw runtime_error(
            "listaddressgroupings\n"
            "Lists groups of addresses which have had their common ownership\n"
            "made public by common use as inputs or as the resulting change\n"
            "in past transactions");

    Array jsonGroupings;
    map<CTxDestination, int64_t> balances = pwalletMain->GetAddressBalances();
    BOOST_FOREACH(set<CTxDestination> grouping, pwalletMain->GetAddressGroupings())
    {
        Array jsonGrouping;
        BOOST_FOREACH(CTxDestination address, grouping)
        {
            Array addressInfo;
            addressInfo.push_back(CBitcoinAddress(address).ToString());
            addressInfo.push_back(ValueFromAmount(balances[address]));
            {
                LOCK(pwalletMain->cs_wallet);
                if (pwalletMain->mapAddressBook.find(CBitcoinAddress(address).Get()) != pwalletMain->mapAddressBook.end())
                    addressInfo.push_back(pwalletMain->mapAddressBook.find(CBitcoinAddress(address).Get())->second);
            }
            jsonGrouping.push_back(addressInfo);
        }
        jsonGroupings.push_back(jsonGrouping);
    }
    return jsonGroupings;
}

Value signmessage(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "signmessage <vpncoinaddress> <message>\n"
            "Sign a message with the private key of an address");

    EnsureWalletIsUnlocked();

    string strAddress = params[0].get_str();
    string strMessage = params[1].get_str();

    CBitcoinAddress addr(strAddress);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    CKey key;
    if (!pwalletMain->GetKey(keyID, key))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key not available");

    CDataStream ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    vector<unsigned char> vchSig;
    if (!key.SignCompact(Hash(ss.begin(), ss.end()), vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return EncodeBase64(&vchSig[0], vchSig.size());
}

Value verifymessage(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "verifymessage <vpncoinaddress> <signature> <message>\n"
            "Verify a signed message");

    string strAddress  = params[0].get_str();
    string strSign     = params[1].get_str();
    string strMessage  = params[2].get_str();

    CBitcoinAddress addr(strAddress);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    bool fInvalid = false;
    vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

    if (fInvalid)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");

    CDataStream ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CKey key;
    if (!key.SetCompactSignature(Hash(ss.begin(), ss.end()), vchSig))
        return false;

    return (key.GetPubKey().GetID() == keyID);
}


Value getreceivedbyaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getreceivedbyaddress <vpncoinaddress> [minconf=1]\n"
            "Returns the total amount received by <vpncoinaddress> in transactions with at least [minconf] confirmations.");

    // Bitcoin address
    CBitcoinAddress address = CBitcoinAddress(params[0].get_str());
    CScript scriptPubKey;
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid VpnCoin address");
    scriptPubKey.SetDestination(address.Get());
    if (!IsMine(*pwalletMain,scriptPubKey))
        return (double)0.0;

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();

    // Tally
    int64_t nAmount = 0;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || wtx.IsCoinStake() || !IsFinalTx(wtx))
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
            if (txout.scriptPubKey == scriptPubKey)
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
    }

    return  ValueFromAmount(nAmount);
}


void GetAccountAddresses(string strAccount, set<CTxDestination>& setAddress)
{
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, pwalletMain->mapAddressBook)
    {
        const CTxDestination& address = item.first;
        const string& strName = item.second;
        if (strName == strAccount)
            setAddress.insert(address);
    }
}

Value getreceivedbyaccount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getreceivedbyaccount <account> [minconf=1]\n"
            "Returns the total amount received by addresses with <account> in transactions with at least [minconf] confirmations.");

    accountingDeprecationCheck();

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();

    // Get the set of pub keys assigned to account
    string strAccount = AccountFromValue(params[0]);
    set<CTxDestination> setAddress;
    GetAccountAddresses(strAccount, setAddress);

    // Tally
    int64_t nAmount = 0;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || wtx.IsCoinStake() || !IsFinalTx(wtx))
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        {
            CTxDestination address;
            if (ExtractDestination(txout.scriptPubKey, address) && IsMine(*pwalletMain, address) && setAddress.count(address))
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
        }
    }

    return (double)nAmount / (double)COIN;
}

int64_t GetAccountBalance(CWalletDB& walletdb, const string& strAccount, int nMinDepth)
{
    int64_t nBalance = 0;

    // Tally wallet transactions
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
		int nDepth = wtx.GetDepthInMainChain();
        if (!IsFinalTx(wtx) || nDepth < 0 ) //wtx.GetDepthInMainChain() < 0)
            continue;
		
//if( fDebug ){ printf("nMinDepth = [%u] [%u]\n", nMinDepth, nDepth); }		
		if( nMinDepth == 0 ){ nMinDepth = nDepth; }

        int64_t nReceived, nSent, nFee;
		//if( strAccount != NULL ){ wtx.strFromAccount = strprintf("%s", strAccount.c_str()); } //--2015.02.22 add 
        wtx.GetAccountAmounts(strAccount, nReceived, nSent, nFee);
		
//if( fDebug ){ printf("[%s] nBalance = [%I64u] [%I64u] [%I64u] [%I64u]\n", strAccount.c_str(), nBalance, nReceived, nSent, nFee); }		

        if( nMinDepth == 0 )
		{
			if( nReceived > 0 ){ 
				nBalance = nBalance + nReceived; 
			}
			nBalance -= nSent + nFee;
		}
		else {
		if (nReceived != 0 && wtx.GetDepthInMainChain() >= nMinDepth && wtx.GetBlocksToMaturity() == 0)
            nBalance += nReceived;
        nBalance -= nSent + nFee;
		}
    }

    // Tally internal accounting entries
	int64_t n2 = walletdb.GetAccountCreditDebit(strAccount);
//if( fDebug ){ printf("[%s] nBalance = [%I64u] [%I64u]\n", strAccount.c_str(), nBalance, n2); }
    nBalance += n2; //walletdb.GetAccountCreditDebit(strAccount);

    return nBalance;
}

int64_t GetAccountBalance(const string& strAccount, int nMinDepth)
{
    CWalletDB walletdb(pwalletMain->strWalletFile);
    return GetAccountBalance(walletdb, strAccount, nMinDepth);
}


Value getbalance(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "getbalance [account] [minconf=1]\n"
            "If [account] is not specified, returns the server's total available balance.\n"
            "If [account] is specified, returns the balance in the account.");

    if (params.size() == 0)
        return  ValueFromAmount(pwalletMain->GetBalance());

    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();

    if (params[0].get_str() == "*") {
        // Calculate total balance a different way from GetBalance()
        // (GetBalance() sums up all unspent TxOuts)
        // getbalance and getbalance '*' 0 should return the same number.
        int64_t nBalance = 0;
        for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
        {
            const CWalletTx& wtx = (*it).second;
            if (!wtx.IsTrusted())
                continue;

            int64_t allFee;
            string strSentAccount;
            list<pair<CTxDestination, int64_t> > listReceived;
            list<pair<CTxDestination, int64_t> > listSent;
            wtx.GetAmounts(listReceived, listSent, allFee, strSentAccount);
            if (wtx.GetDepthInMainChain() >= nMinDepth && wtx.GetBlocksToMaturity() == 0)
            {
                BOOST_FOREACH(const PAIRTYPE(CTxDestination,int64_t)& r, listReceived)
                    nBalance += r.second;
            }
            BOOST_FOREACH(const PAIRTYPE(CTxDestination,int64_t)& r, listSent)
                nBalance -= r.second;
            nBalance -= allFee;
        }
        return  ValueFromAmount(nBalance);
    }

    accountingDeprecationCheck();

    string strAccount = AccountFromValue(params[0]);

    int64_t nBalance = GetAccountBalance(strAccount, nMinDepth);

    return ValueFromAmount(nBalance);
}


Value movecmd(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 5)
        throw runtime_error(
            "move <fromaccount> <toaccount> <amount> [minconf=1] [comment]\n"
            "Move from one account in your wallet to another.");

    accountingDeprecationCheck();

    string strFrom = AccountFromValue(params[0]);
    string strTo = AccountFromValue(params[1]);
    int64_t nAmount = AmountFromValue(params[2]);

    if (params.size() > 3)
        // unused parameter, used to be nMinDepth, keep type-checking it though
        (void)params[3].get_int();
    string strComment;
    if (params.size() > 4)
        strComment = params[4].get_str();

    CWalletDB walletdb(pwalletMain->strWalletFile);
    if (!walletdb.TxnBegin())
        throw JSONRPCError(RPC_DATABASE_ERROR, "database error");

    int64_t nNow = GetAdjustedTime();

    // Debit
    CAccountingEntry debit;
    debit.nOrderPos = pwalletMain->IncOrderPosNext(&walletdb);
    debit.strAccount = strFrom;
    debit.nCreditDebit = -nAmount;
    debit.nTime = nNow;
    debit.strOtherAccount = strTo;
    debit.strComment = strComment;
    walletdb.WriteAccountingEntry(debit);

    // Credit
    CAccountingEntry credit;
    credit.nOrderPos = pwalletMain->IncOrderPosNext(&walletdb);
    credit.strAccount = strTo;
    credit.nCreditDebit = nAmount;
    credit.nTime = nNow;
    credit.strOtherAccount = strFrom;
    credit.strComment = strComment;
    walletdb.WriteAccountingEntry(credit);

    if (!walletdb.TxnCommit())
        throw JSONRPCError(RPC_DATABASE_ERROR, "database error");

    return true;
}

Value sendfrom(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 6)
        throw runtime_error(
            "sendfrom <fromaccount> <tovpncoinaddress> <amount> [minconf=1] [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest 0.000001"
            + HelpRequiringPassphrase());

    string strAccount = AccountFromValue(params[0]);
    CBitcoinAddress address(params[1].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid VpnCoin address");
    int64_t nAmount = AmountFromValue(params[2]);

    int nMinDepth = 1;
    if (params.size() > 3)
        nMinDepth = params[3].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (params.size() > 4 && params[4].type() != null_type && !params[4].get_str().empty())
        wtx.mapValue["comment"] = params[4].get_str();
    if (params.size() > 5 && params[5].type() != null_type && !params[5].get_str().empty())
        wtx.mapValue["to"]      = params[5].get_str();

    EnsureWalletIsUnlocked();

    // Check funds
    int64_t nBalance = GetAccountBalance(strAccount, nMinDepth);
if( fDebug ){ printf("sendfrom [%s] nTotalBalance: [%I64u] : [%I64u]\n", strAccount.c_str(), nAmount, nBalance); }
    if (nAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    // Send
	string stxData = "";
    string strError = pwalletMain->SendMoneyToDestination(address.Get(), nAmount, wtx, stxData);
    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    return wtx.GetHash().GetHex();
}


Value sendmany(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
        throw runtime_error(
            "sendmany <fromaccount> {address:amount,...} [minconf=1] [comment]\n"
            "amounts are double-precision floating point numbers"
            + HelpRequiringPassphrase());

    string strAccount = AccountFromValue(params[0]);
    Object sendTo = params[1].get_obj();
    int nMinDepth = 1;
    if (params.size() > 2)
        nMinDepth = params[2].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (params.size() > 3 && params[3].type() != null_type && !params[3].get_str().empty())
        wtx.mapValue["comment"] = params[3].get_str();

    set<CBitcoinAddress> setAddress;
    vector<pair<CScript, int64_t> > vecSend;

    int64_t totalAmount = 0;
    BOOST_FOREACH(const Pair& s, sendTo)
    {
        CBitcoinAddress address(s.name_);
        if (!address.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid VpnCoin address: ")+s.name_);

        if (setAddress.count(address))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+s.name_);
        setAddress.insert(address);

        CScript scriptPubKey;
        scriptPubKey.SetDestination(address.Get());
        int64_t nAmount = AmountFromValue(s.value_);

        totalAmount += nAmount;

        vecSend.push_back(make_pair(scriptPubKey, nAmount));
    }

    EnsureWalletIsUnlocked();

    // Check funds
    int64_t nBalance = GetAccountBalance(strAccount, nMinDepth);
    if (totalAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    // Send
	std::string stxData;
    CReserveKey keyChange(pwalletMain);
    int64_t nFeeRequired = 0;
    bool fCreated = pwalletMain->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, stxData, 1);
    if (!fCreated)
    {
        if (totalAmount + nFeeRequired > pwalletMain->GetBalance())
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");
        throw JSONRPCError(RPC_WALLET_ERROR, "Transaction creation failed");
    }
    if (!pwalletMain->CommitTransaction(wtx, keyChange))
        throw JSONRPCError(RPC_WALLET_ERROR, "Transaction commit failed");

    return wtx.GetHash().GetHex();
}

Value addmultisigaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
    {
        string msg = "addmultisigaddress <nrequired> <'[\"key\",\"key\"]'> [account]\n"
            "Add a nrequired-to-sign multisignature address to the wallet\"\n"
            "each key is a VpnCoin address or hex-encoded public key\n"
            "If [account] is specified, assign address to [account].";
        throw runtime_error(msg);
    }

    int nRequired = params[0].get_int();
    const Array& keys = params[1].get_array();
    string strAccount;
    if (params.size() > 2)
        strAccount = AccountFromValue(params[2]);

    // Gather public keys
    if (nRequired < 1)
        throw runtime_error("a multisignature address must require at least one key to redeem");
    if ((int)keys.size() < nRequired)
        throw runtime_error(
            strprintf("not enough keys supplied "
                      "(got %"PRIszu" keys, but need at least %d to redeem)", keys.size(), nRequired));
    std::vector<CKey> pubkeys;
    pubkeys.resize(keys.size());
    for (unsigned int i = 0; i < keys.size(); i++)
    {
        const std::string& ks = keys[i].get_str();

        // Case 1: Bitcoin address and we have full public key:
        CBitcoinAddress address(ks);
        if (address.IsValid())
        {
            CKeyID keyID;
            if (!address.GetKeyID(keyID))
                throw runtime_error(
                    strprintf("%s does not refer to a key",ks.c_str()));
            CPubKey vchPubKey;
            if (!pwalletMain->GetPubKey(keyID, vchPubKey))
                throw runtime_error(
                    strprintf("no full public key for address %s",ks.c_str()));
            if (!vchPubKey.IsValid() || !pubkeys[i].SetPubKey(vchPubKey))
                throw runtime_error(" Invalid public key: "+ks);
        }

        // Case 2: hex public key
        else if (IsHex(ks))
        {
            CPubKey vchPubKey(ParseHex(ks));
            if (!vchPubKey.IsValid() || !pubkeys[i].SetPubKey(vchPubKey))
                throw runtime_error(" Invalid public key: "+ks);
        }
        else
        {
            throw runtime_error(" Invalid public key: "+ks);
        }
    }

    // Construct using pay-to-script-hash:
    CScript inner;
    inner.SetMultisig(nRequired, pubkeys);
    CScriptID innerID = inner.GetID();
    if (!pwalletMain->AddCScript(inner))
        throw runtime_error("AddCScript() failed");

    pwalletMain->SetAddressBookName(innerID, strAccount);
    return CBitcoinAddress(innerID).ToString();
}

Value addredeemscript(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
    {
        string msg = "addredeemscript <redeemScript> [account]\n"
            "Add a P2SH address with a specified redeemScript to the wallet.\n"
            "If [account] is specified, assign address to [account].";
        throw runtime_error(msg);
    }

    string strAccount;
    if (params.size() > 1)
        strAccount = AccountFromValue(params[1]);

    // Construct using pay-to-script-hash:
    vector<unsigned char> innerData = ParseHexV(params[0], "redeemScript");
    CScript inner(innerData.begin(), innerData.end());
    CScriptID innerID = inner.GetID();
    if (!pwalletMain->AddCScript(inner))
        throw runtime_error("AddCScript() failed");

    pwalletMain->SetAddressBookName(innerID, strAccount);
    return CBitcoinAddress(innerID).ToString();
}

struct tallyitem
{
    int64_t nAmount;
    int nConf;
    tallyitem()
    {
        nAmount = 0;
        nConf = std::numeric_limits<int>::max();
    }
};

Value ListReceived(const Array& params, bool fByAccounts)
{
    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int();

    // Whether to include empty accounts
    bool fIncludeEmpty = false;
    if (params.size() > 1)
        fIncludeEmpty = params[1].get_bool();

    // Tally
    map<CBitcoinAddress, tallyitem> mapTally;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;

        if (wtx.IsCoinBase() || wtx.IsCoinStake() || !IsFinalTx(wtx))
            continue;

        int nDepth = wtx.GetDepthInMainChain();
        if (nDepth < nMinDepth)
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        {
            CTxDestination address;
            if (!ExtractDestination(txout.scriptPubKey, address) || !IsMine(*pwalletMain, address))
                continue;

            tallyitem& item = mapTally[address];
            item.nAmount += txout.nValue;
            item.nConf = min(item.nConf, nDepth);
        }
    }

    // Reply
    Array ret;
    map<string, tallyitem> mapAccountTally;
    BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, string)& item, pwalletMain->mapAddressBook)
    {
        const CBitcoinAddress& address = item.first;
        const string& strAccount = item.second;
        map<CBitcoinAddress, tallyitem>::iterator it = mapTally.find(address);
        if (it == mapTally.end() && !fIncludeEmpty)
            continue;

        int64_t nAmount = 0;
        int nConf = std::numeric_limits<int>::max();
        if (it != mapTally.end())
        {
            nAmount = (*it).second.nAmount;
            nConf = (*it).second.nConf;
        }

        if (fByAccounts)
        {
            tallyitem& item = mapAccountTally[strAccount];
            item.nAmount += nAmount;
            item.nConf = min(item.nConf, nConf);
        }
        else
        {
            Object obj;
            obj.push_back(Pair("address",       address.ToString()));
            obj.push_back(Pair("account",       strAccount));
            obj.push_back(Pair("amount",        ValueFromAmount(nAmount)));
            obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
            ret.push_back(obj);
        }
    }

    if (fByAccounts)
    {
        for (map<string, tallyitem>::iterator it = mapAccountTally.begin(); it != mapAccountTally.end(); ++it)
        {
            int64_t nAmount = (*it).second.nAmount;
            int nConf = (*it).second.nConf;
            Object obj;
            obj.push_back(Pair("account",       (*it).first));
            obj.push_back(Pair("amount",        ValueFromAmount(nAmount)));
            obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
            ret.push_back(obj);
        }
    }

    return ret;
}

Value listreceivedbyaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "listreceivedbyaddress [minconf=1] [includeempty=false]\n"
            "[minconf] is the minimum number of confirmations before payments are included.\n"
            "[includeempty] whether to include addresses that haven't received any payments.\n"
            "Returns an array of objects containing:\n"
            "  \"address\" : receiving address\n"
            "  \"account\" : the account of the receiving address\n"
            "  \"amount\" : total amount received by the address\n"
            "  \"confirmations\" : number of confirmations of the most recent transaction included");

    return ListReceived(params, false);
}

Value listreceivedbyaccount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "listreceivedbyaccount [minconf=1] [includeempty=false]\n"
            "[minconf] is the minimum number of confirmations before payments are included.\n"
            "[includeempty] whether to include accounts that haven't received any payments.\n"
            "Returns an array of objects containing:\n"
            "  \"account\" : the account of the receiving addresses\n"
            "  \"amount\" : total amount received by addresses with this account\n"
            "  \"confirmations\" : number of confirmations of the most recent transaction included");

    accountingDeprecationCheck();

    return ListReceived(params, true);
}

static void MaybePushAddress(Object & entry, const CTxDestination &dest)
{
    CBitcoinAddress addr;
    if (addr.Set(dest))
        entry.push_back(Pair("address", addr.ToString()));
}

void ListTransactions(const CWalletTx& wtx, const string& strAccount, int nMinDepth, bool fLong, Array& ret)
{
    int64_t nFee;
    string strSentAccount;
    list<pair<CTxDestination, int64_t> > listReceived;
    list<pair<CTxDestination, int64_t> > listSent;

    wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount);

    bool fAllAccounts = (strAccount == string("*"));

    // Sent
    if ((!wtx.IsCoinStake()) && (!listSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount))
    {
        BOOST_FOREACH(const PAIRTYPE(CTxDestination, int64_t)& s, listSent)
        {
            Object entry;
            entry.push_back(Pair("account", strSentAccount));
            MaybePushAddress(entry, s.first);
            entry.push_back(Pair("category", "send"));
            entry.push_back(Pair("amount", ValueFromAmount(-s.second)));
            entry.push_back(Pair("fee", ValueFromAmount(-nFee)));
            if (fLong)
                WalletTxToJSON(wtx, entry);
            ret.push_back(entry);
        }
    }

    // Received
    if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= nMinDepth)
    {
        bool stop = false;
        BOOST_FOREACH(const PAIRTYPE(CTxDestination, int64_t)& r, listReceived)
        {
            string account;
            if (pwalletMain->mapAddressBook.count(r.first))
                account = pwalletMain->mapAddressBook[r.first];
            if (fAllAccounts || (account == strAccount))
            {
                Object entry;
                entry.push_back(Pair("account", account));
                MaybePushAddress(entry, r.first);
                if (wtx.IsCoinBase() || wtx.IsCoinStake())
                {
                    if (wtx.GetDepthInMainChain() < 1)
                        entry.push_back(Pair("category", "orphan"));
                    else if (wtx.GetBlocksToMaturity() > 0)
                        entry.push_back(Pair("category", "immature"));
                    else
                        entry.push_back(Pair("category", "generate"));
                }
                else
                {
                    entry.push_back(Pair("category", "receive"));
                }
                if (!wtx.IsCoinStake())
                    entry.push_back(Pair("amount", ValueFromAmount(r.second)));
                else
                {
                    entry.push_back(Pair("amount", ValueFromAmount(-nFee)));
                    stop = true; // only one coinstake output
                }
                if (fLong)
                    WalletTxToJSON(wtx, entry);
                ret.push_back(entry);
            }
            if (stop)
                break;
        }
    }
}

void AcentryToJSON(const CAccountingEntry& acentry, const string& strAccount, Array& ret)
{
    bool fAllAccounts = (strAccount == string("*"));

    if (fAllAccounts || acentry.strAccount == strAccount)
    {
        Object entry;
        entry.push_back(Pair("account", acentry.strAccount));
        entry.push_back(Pair("category", "move"));
        entry.push_back(Pair("time", (int64_t)acentry.nTime));
        entry.push_back(Pair("amount", ValueFromAmount(acentry.nCreditDebit)));
        entry.push_back(Pair("otheraccount", acentry.strOtherAccount));
        entry.push_back(Pair("comment", acentry.strComment));
        ret.push_back(entry);
    }
}

Value listtransactions(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 3)
        throw runtime_error(
            "listtransactions [account] [count=10] [from=0]\n"
            "Returns up to [count] most recent transactions skipping the first [from] transactions for account [account].");

    string strAccount = "*";
    if (params.size() > 0)
        strAccount = params[0].get_str();
    int nCount = 10;
    if (params.size() > 1)
        nCount = params[1].get_int();
    int nFrom = 0;
    if (params.size() > 2)
        nFrom = params[2].get_int();

    if (nCount < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
    if (nFrom < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");

    Array ret;

    std::list<CAccountingEntry> acentries;
    CWallet::TxItems txOrdered = pwalletMain->OrderedTxItems(acentries, strAccount);

    // iterate backwards until we have nCount items to return:
    for (CWallet::TxItems::reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
    {
        CWalletTx *const pwtx = (*it).second.first;
        if (pwtx != 0)
            ListTransactions(*pwtx, strAccount, 0, true, ret);
        CAccountingEntry *const pacentry = (*it).second.second;
        if (pacentry != 0)
            AcentryToJSON(*pacentry, strAccount, ret);

        if ((int)ret.size() >= (nCount+nFrom)) break;
    }
    // ret is newest to oldest

    if (nFrom > (int)ret.size())
        nFrom = ret.size();
    if ((nFrom + nCount) > (int)ret.size())
        nCount = ret.size() - nFrom;
    Array::iterator first = ret.begin();
    std::advance(first, nFrom);
    Array::iterator last = ret.begin();
    std::advance(last, nFrom+nCount);

    if (last != ret.end()) ret.erase(last, ret.end());
    if (first != ret.begin()) ret.erase(ret.begin(), first);

    std::reverse(ret.begin(), ret.end()); // Return oldest to newest

    return ret;
}

Value listaccounts(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "listaccounts [minconf=1]\n"
            "Returns Object that has account names as keys, account balances as values.");

    accountingDeprecationCheck();

    int nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int();

    map<string, int64_t> mapAccountBalances;
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, pwalletMain->mapAddressBook) {
        if (IsMine(*pwalletMain, entry.first)) // This address belongs to me
            mapAccountBalances[entry.second] = 0;
    }

    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        int64_t nFee;
        string strSentAccount;
        list<pair<CTxDestination, int64_t> > listReceived;
        list<pair<CTxDestination, int64_t> > listSent;
        int nDepth = wtx.GetDepthInMainChain();
        if (nDepth < 0)
            continue;
        wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount);
        mapAccountBalances[strSentAccount] -= nFee;
        BOOST_FOREACH(const PAIRTYPE(CTxDestination, int64_t)& s, listSent)
            mapAccountBalances[strSentAccount] -= s.second;
        if (nDepth >= nMinDepth && wtx.GetBlocksToMaturity() == 0)
        {
            BOOST_FOREACH(const PAIRTYPE(CTxDestination, int64_t)& r, listReceived)
                if (pwalletMain->mapAddressBook.count(r.first))
                    mapAccountBalances[pwalletMain->mapAddressBook[r.first]] += r.second;
                else
                    mapAccountBalances[""] += r.second;
        }
    }

    list<CAccountingEntry> acentries;
    CWalletDB(pwalletMain->strWalletFile).ListAccountCreditDebit("*", acentries);
    BOOST_FOREACH(const CAccountingEntry& entry, acentries)
        mapAccountBalances[entry.strAccount] += entry.nCreditDebit;

    Object ret;
    BOOST_FOREACH(const PAIRTYPE(string, int64_t)& accountBalance, mapAccountBalances) {
        ret.push_back(Pair(accountBalance.first, ValueFromAmount(accountBalance.second)));
    }
    return ret;
}

Value listsinceblock(const Array& params, bool fHelp)
{
    if (fHelp)
        throw runtime_error(
            "listsinceblock [blockhash] [target-confirmations]\n"
            "Get all transactions in blocks since block [blockhash], or all transactions if omitted");

    CBlockIndex *pindex = NULL;
    int target_confirms = 1;

    if (params.size() > 0)
    {
        uint256 blockId = 0;

        blockId.SetHex(params[0].get_str());
        pindex = CBlockLocator(blockId).GetBlockIndex();
    }

    if (params.size() > 1)
    {
        target_confirms = params[1].get_int();

        if (target_confirms < 1)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
    }

    int depth = pindex ? (1 + nBestHeight - pindex->nHeight) : -1;

    Array transactions;

    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); it++)
    {
        CWalletTx tx = (*it).second;

        if (depth == -1 || tx.GetDepthInMainChain() < depth)
            ListTransactions(tx, "*", 0, true, transactions);
    }

    uint256 lastblock;

    if (target_confirms == 1)
    {
        lastblock = hashBestChain;
    }
    else
    {
        int target_height = pindexBest->nHeight + 1 - target_confirms;

        CBlockIndex *block;
        for (block = pindexBest;
             block && block->nHeight > target_height;
             block = block->pprev)  { }

        lastblock = block ? block->GetBlockHash() : 0;
    }

    Object ret;
    ret.push_back(Pair("transactions", transactions));
    ret.push_back(Pair("lastblock", lastblock.GetHex()));

    return ret;
}

Value gettransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "gettransaction <txid>\n"
            "Get detailed information about <txid>");

    uint256 hash;
    hash.SetHex(params[0].get_str());

    Object entry;

    if (pwalletMain->mapWallet.count(hash))
    {
        const CWalletTx& wtx = pwalletMain->mapWallet[hash];

        TxToJSON(wtx, 0, entry);

        int64_t nCredit = wtx.GetCredit();
        int64_t nDebit = wtx.GetDebit();
        int64_t nNet = nCredit - nDebit;
        int64_t nFee = (wtx.IsFromMe() ? wtx.GetValueOut() - nDebit : 0);

        entry.push_back(Pair("amount", ValueFromAmount(nNet - nFee)));
        if (wtx.IsFromMe())
            entry.push_back(Pair("fee", ValueFromAmount(nFee)));

        WalletTxToJSON(wtx, entry);

        Array details;
        ListTransactions(pwalletMain->mapWallet[hash], "*", 0, false, details);
        entry.push_back(Pair("details", details));
    }
    else
    {
        CTransaction tx;
        uint256 hashBlock = 0;
        if (GetTransaction(hash, tx, hashBlock))
        {
            TxToJSON(tx, 0, entry);
            if (hashBlock == 0)
                entry.push_back(Pair("confirmations", 0));
            else
            {
                entry.push_back(Pair("blockhash", hashBlock.GetHex()));
                map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
                if (mi != mapBlockIndex.end() && (*mi).second)
                {
                    CBlockIndex* pindex = (*mi).second;
                    if (pindex->IsInMainChain())
                        entry.push_back(Pair("confirmations", 1 + nBestHeight - pindex->nHeight));
                    else
                        entry.push_back(Pair("confirmations", 0));
                }
            }
        }
        else
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");
    }

    return entry;
}


Value backupwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "backupwallet <destination>\n"
            "Safely copies wallet.dat to destination, which can be a directory or a path with filename.");

    string strDest = params[0].get_str();
    if (!BackupWallet(*pwalletMain, strDest))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet backup failed!");

    return Value::null;
}


Value keypoolrefill(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "keypoolrefill [new-size]\n"
            "Fills the keypool."
            + HelpRequiringPassphrase());

    unsigned int nSize = max(GetArg("-keypool", 100), (int64_t)0);
    if (params.size() > 0) {
        if (params[0].get_int() < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected valid size");
        nSize = (unsigned int) params[0].get_int();
    }

    EnsureWalletIsUnlocked();

    pwalletMain->TopUpKeyPool(nSize);

    if (pwalletMain->GetKeyPoolSize() < nSize)
        throw JSONRPCError(RPC_WALLET_ERROR, "Error refreshing keypool.");

    return Value::null;
}


void ThreadTopUpKeyPool(void* parg)
{
    // Make this thread recognisable as the key-topping-up thread
    RenameThread("vpncoin-key-top");

    pwalletMain->TopUpKeyPool();
}

void ThreadCleanWalletPassphrase(void* parg)
{
    // Make this thread recognisable as the wallet relocking thread
    RenameThread("vpncoin-lock-wa");

    int64_t nMyWakeTime = GetTimeMillis() + *((int64_t*)parg) * 1000;

    ENTER_CRITICAL_SECTION(cs_nWalletUnlockTime);

    if (nWalletUnlockTime == 0)
    {
        nWalletUnlockTime = nMyWakeTime;

        do
        {
            if (nWalletUnlockTime==0)
                break;
            int64_t nToSleep = nWalletUnlockTime - GetTimeMillis();
            if (nToSleep <= 0)
                break;

            LEAVE_CRITICAL_SECTION(cs_nWalletUnlockTime);
            MilliSleep(nToSleep);
            ENTER_CRITICAL_SECTION(cs_nWalletUnlockTime);

        } while(1);

        if (nWalletUnlockTime)
        {
            nWalletUnlockTime = 0;
            pwalletMain->Lock();
        }
    }
    else
    {
        if (nWalletUnlockTime < nMyWakeTime)
            nWalletUnlockTime = nMyWakeTime;
    }

    LEAVE_CRITICAL_SECTION(cs_nWalletUnlockTime);

    delete (int64_t*)parg;
}

Value walletpassphrase(const Array& params, bool fHelp)
{
    if (pwalletMain->IsCrypted() && (fHelp || params.size() < 2 || params.size() > 3))
        throw runtime_error(
            "walletpassphrase <passphrase> <timeout> [stakingonly]\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.\n"
            "if [stakingonly] is true sending functions are disabled.");
    if (fHelp)
        return true;
    if (!pwalletMain->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrase was called.");

    if (!pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_ALREADY_UNLOCKED, "Error: Wallet is already unlocked, use walletlock first if need to change unlock settings.");

    int64_t nSleepTime = params[1].get_int64();
    if (nSleepTime <= 0 || nSleepTime >= std::numeric_limits<int64_t>::max() / 1000000000)
        throw runtime_error("timeout is out of bounds");

    // Note that the walletpassphrase is stored in params[0] which is not mlock()ed
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    strWalletPass = params[0].get_str().c_str();

    if (strWalletPass.length() > 0)
    {
        if (!pwalletMain->Unlock(strWalletPass))
            throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
    }
    else
        throw runtime_error(
            "walletpassphrase <passphrase> <timeout>\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.");

    NewThread(ThreadTopUpKeyPool, NULL);
    int64_t* pnSleepTime = new int64_t(nSleepTime);
    NewThread(ThreadCleanWalletPassphrase, pnSleepTime);

    // ppcoin: if user OS account compromised prevent trivial sendmoney commands
    if (params.size() > 2)
        fWalletUnlockStakingOnly = params[2].get_bool();
    else
        fWalletUnlockStakingOnly = false;

    return Value::null;
}


Value walletpassphrasechange(const Array& params, bool fHelp)
{
    if (pwalletMain->IsCrypted() && (fHelp || params.size() != 2))
        throw runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");
    if (fHelp)
        return true;
    if (!pwalletMain->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrasechange was called.");

    // TODO: get rid of these .c_str() calls by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    SecureString strOldWalletPass;
    strOldWalletPass.reserve(100);
    strOldWalletPass = params[0].get_str().c_str();

    SecureString strNewWalletPass;
    strNewWalletPass.reserve(100);
    strNewWalletPass = params[1].get_str().c_str();

    if (strOldWalletPass.length() < 1 || strNewWalletPass.length() < 1)
        throw runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");

    if (!pwalletMain->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass))
        throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");

    return Value::null;
}


Value walletlock(const Array& params, bool fHelp)
{
    if (pwalletMain->IsCrypted() && (fHelp || params.size() != 0))
        throw runtime_error(
            "walletlock\n"
            "Removes the wallet encryption key from memory, locking the wallet.\n"
            "After calling this method, you will need to call walletpassphrase again\n"
            "before being able to call any methods which require the wallet to be unlocked.");
    if (fHelp)
        return true;
    if (!pwalletMain->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletlock was called.");

    {
        LOCK(cs_nWalletUnlockTime);
        pwalletMain->Lock();
        nWalletUnlockTime = 0;
    }

    return Value::null;
}


Value encryptwallet(const Array& params, bool fHelp)
{
    if (!pwalletMain->IsCrypted() && (fHelp || params.size() != 1))
        throw runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");
    if (fHelp)
        return true;
    if (pwalletMain->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an encrypted wallet, but encryptwallet was called.");

    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    strWalletPass = params[0].get_str().c_str();

    if (strWalletPass.length() < 1)
        throw runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");

    if (!pwalletMain->EncryptWallet(strWalletPass))
        throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Error: Failed to encrypt the wallet.");

    // BDB seems to have a bad habit of writing old data into
    // slack space in .dat files; that is bad if the old data is
    // unencrypted private keys. So:
    StartShutdown();
    return "wallet encrypted; VpnCoin server stopping, restart to run with encrypted wallet.  The keypool has been flushed, you need to make a new backup.";
}

class DescribeAddressVisitor : public boost::static_visitor<Object>
{
public:
    Object operator()(const CNoDestination &dest) const { return Object(); }

    Object operator()(const CKeyID &keyID) const {
        Object obj;
        CPubKey vchPubKey;
        pwalletMain->GetPubKey(keyID, vchPubKey);
        obj.push_back(Pair("isscript", false));
        obj.push_back(Pair("pubkey", HexStr(vchPubKey.Raw())));
        obj.push_back(Pair("iscompressed", vchPubKey.IsCompressed()));
        return obj;
    }

    Object operator()(const CScriptID &scriptID) const {
        Object obj;
        obj.push_back(Pair("isscript", true));
        CScript subscript;
        pwalletMain->GetCScript(scriptID, subscript);
        std::vector<CTxDestination> addresses;
        txnouttype whichType;
        int nRequired;
        ExtractDestinations(subscript, whichType, addresses, nRequired);
        obj.push_back(Pair("script", GetTxnOutputType(whichType)));
        obj.push_back(Pair("hex", HexStr(subscript.begin(), subscript.end())));
        Array a;
        BOOST_FOREACH(const CTxDestination& addr, addresses)
            a.push_back(CBitcoinAddress(addr).ToString());
        obj.push_back(Pair("addresses", a));
        if (whichType == TX_MULTISIG)
            obj.push_back(Pair("sigsrequired", nRequired));
        return obj;
    }
};

Value validateaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "validateaddress <vpncoinaddress>\n"
            "Return information about <vpncoinaddress>.");

    CBitcoinAddress address(params[0].get_str());
    bool isValid = address.IsValid();

    Object ret;
    ret.push_back(Pair("isvalid", isValid));
    if (isValid)
    {
        CTxDestination dest = address.Get();
        string currentAddress = address.ToString();
        ret.push_back(Pair("address", currentAddress));
        bool fMine = IsMine(*pwalletMain, dest);
        ret.push_back(Pair("ismine", fMine));
        if (fMine) {
            Object detail = boost::apply_visitor(DescribeAddressVisitor(), dest);
            ret.insert(ret.end(), detail.begin(), detail.end());
        }
        if (pwalletMain->mapAddressBook.count(dest))
            ret.push_back(Pair("account", pwalletMain->mapAddressBook[dest]));
    }
    return ret;
}

Value validatepubkey(const Array& params, bool fHelp)
{
    if (fHelp || !params.size() || params.size() > 2)
        throw runtime_error(
            "validatepubkey <vpncoinpubkey>\n"
            "Return information about <vpncoinpubkey>.");

    std::vector<unsigned char> vchPubKey = ParseHex(params[0].get_str());
    CPubKey pubKey(vchPubKey);

    bool isValid = pubKey.IsValid();
    bool isCompressed = pubKey.IsCompressed();
    CKeyID keyID = pubKey.GetID();

    CBitcoinAddress address;
    address.Set(keyID);

    Object ret;
    ret.push_back(Pair("isvalid", isValid));
    if (isValid)
    {
        CTxDestination dest = address.Get();
        string currentAddress = address.ToString();
        ret.push_back(Pair("address", currentAddress));
        bool fMine = IsMine(*pwalletMain, dest);
        ret.push_back(Pair("ismine", fMine));
        ret.push_back(Pair("iscompressed", isCompressed));
        if (fMine) {
            Object detail = boost::apply_visitor(DescribeAddressVisitor(), dest);
            ret.insert(ret.end(), detail.begin(), detail.end());
        }
        if (pwalletMain->mapAddressBook.count(dest))
            ret.push_back(Pair("account", pwalletMain->mapAddressBook[dest]));
    }
    return ret;
}

// ppcoin: reserve balance from being staked for network protection
Value reservebalance(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "reservebalance [<reserve> [amount]]\n"
            "<reserve> is true or false to turn balance reserve on or off.\n"
            "<amount> is a real and rounded to cent.\n"
            "Set reserve amount not participating in network protection.\n"
            "If no parameters provided current setting is printed.\n");

    if (params.size() > 0)
    {
        bool fReserve = params[0].get_bool();
        if (fReserve)
        {
            if (params.size() == 1)
                throw runtime_error("must provide amount to reserve balance.\n");
            int64_t nAmount = AmountFromValue(params[1]);
            nAmount = (nAmount / CENT) * CENT;  // round to cent
            if (nAmount < 0)
                throw runtime_error("amount cannot be negative.\n");
            nReserveBalance = nAmount;
        }
        else
        {
            if (params.size() > 1)
                throw runtime_error("cannot specify amount to turn off reserve.\n");
            nReserveBalance = 0;
        }
    }

    Object result;
    result.push_back(Pair("reserve", (nReserveBalance > 0)));
    result.push_back(Pair("amount", ValueFromAmount(nReserveBalance)));
    return result;
}


// ppcoin: check wallet integrity
Value checkwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "checkwallet\n"
            "Check wallet for integrity.\n");

    int nMismatchSpent;
    int64_t nBalanceInQuestion;
    pwalletMain->FixSpentCoins(nMismatchSpent, nBalanceInQuestion, true);
    Object result;
    if (nMismatchSpent == 0)
        result.push_back(Pair("wallet check passed", true));
    else
    {
        result.push_back(Pair("mismatched spent coins", nMismatchSpent));
        result.push_back(Pair("amount in question", ValueFromAmount(nBalanceInQuestion)));
    }
    return result;
}


// ppcoin: repair wallet
Value repairwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "repairwallet(xfqb)\n"
            "Repair wallet if checkwallet reports any problem.\n");

    int nMismatchSpent;
    int64_t nBalanceInQuestion;
    pwalletMain->FixSpentCoins(nMismatchSpent, nBalanceInQuestion);
    Object result;
    if (nMismatchSpent == 0)
        result.push_back(Pair("wallet check passed", true));
    else
    {
        result.push_back(Pair("mismatched spent coins", nMismatchSpent));
        result.push_back(Pair("amount affected by repair", ValueFromAmount(nBalanceInQuestion)));
    }
    return result;
}

// NovaCoin: resend unconfirmed wallet transactions
Value resendtx(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "resendtx\n"
            "Re-send unconfirmed transactions.\n"
        );

    ResendWalletTransactions(true);

    return Value::null;
}

// ppcoin: make a public-private key pair
Value makekeypair(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "makekeypair [prefix]\n"
            "Make a public/private key pair.\n"
            "[prefix] is optional preferred prefix for the public key.\n");

    string strPrefix = "";
    if (params.size() > 0)
        strPrefix = params[0].get_str();
 
    CKey key;
    key.MakeNewKey(false);

    CPrivKey vchPrivKey = key.GetPrivKey();
    Object result;
    result.push_back(Pair("PrivateKey", HexStr<CPrivKey::iterator>(vchPrivKey.begin(), vchPrivKey.end())));
    result.push_back(Pair("PublicKey", HexStr(key.GetPubKey().Raw())));
    return result;
}

//--2015.04.13 add
int dwBitNetLotteryStartBlock_32W = 320000;
int BitNetLotteryStartTestBlock_286000 = 286000;
int64_t BitNet_Lottery_Create_Mini_Amount_5K = 5000 * COIN;
extern const string strBitNetLotteryMagic;	// "BitNet Lottery:"
extern const int iBitNetBlockMargin3;			// 3
extern const int BitNetBeginAndEndBlockMargin_Mini_30;		// 30
extern const int BitNetBeginAndEndBlockMargin_Max_4320;	// 4320
extern const int64_t MIN_Lottery_Create_Amount;	// 100, test

bool isBitNetLotteryRuleStart()
{
	return nBestHeight >= dwBitNetLotteryStartBlock_32W;
}

int64_t S_To_64(const char *s) 
{
  int64_t i;
  char c ;
  int scanned = sscanf(s, "%" SCNd64 "%c", &i, &c);
  if (scanned == 1) return i;
  if (scanned > 1) {
    // TBD about extra data found
    return i;
    }
  // TBD failed to scan;  
  return 0;  
}

string getStrDigitalAddValueStr(const string aStr, int aLen)
{
	string rzt = "";
	int j = aStr.length();
	if( (aLen > 0) && (j >= aLen) )
	{
		PCHAR p = (PCHAR)aStr.c_str();
		int r = 0;
		for( int i = 0; i < aLen; i++ )
		{
			unsigned char b = (unsigned char)p[i];
			if( (b > 0x2F) && (b < 0x3A) ){ r = r + (b - 0x30); }		// '0' ~ '9' = 0x30 ~ 0x39
			else if( (b > 0x60) && (b < 0x67) ){ r = r + (b - 0x57); }	// 'a' ~ 'f' = 0x61 ~ 0x66
		}
		rzt = strprintf("%d", r);
	}
	return rzt;
}

int  GetCoinAddrInTxOutIndex(const CTransaction& tx, string sAddr, int64_t v_nValue, int iCmpType)
{
	int rzt = -1;
	if( IsFinalTx(tx, nBestHeight + 1) )
	{
		//BOOST_FOREACH(const CTxOut& txout, tx.vout) 	
		for (unsigned int i = 0; i < tx.vout.size(); i++)
		{
			const CTxOut& txout = tx.vout[i];
			bool bOk = false;
			if( v_nValue == 0 ){ bOk = true; }	 // = 0 mean Ignore nValue param
			else
			{
				if( iCmpType == 0 ){ if( txout.nValue == v_nValue ){ bOk = true; } }		// equ
				else if( iCmpType == 1 ){ if( txout.nValue < v_nValue ){ bOk = true; } }	// less
				else if( iCmpType == 2 ){ if( txout.nValue > v_nValue ){ bOk = true; } }	// big
				else if( iCmpType == 3 ){ if( txout.nValue >= v_nValue ){ bOk = true; } }	// equ or big
			}
		
			if( bOk ) //if( txout.nValue == v_nValue )
			{	
				txnouttype type;
				vector<CTxDestination> addresses;
				int nRequired;
				if( ExtractDestinations(txout.scriptPubKey, type, addresses, nRequired) )
				{
					BOOST_FOREACH(const CTxDestination& addr, addresses)
					{
						string sAa = CBitcoinAddress(addr).ToString();
						if( sAa == sAddr ){ return i; }
					}
				}
			}
		}
	}
	return rzt;
}
int  GetCoinAddrInTxOutIndex(const string txID, string sAddr, int64_t v_nValue, int iCmpType)
{
	int rzt = -1;
	if( txID.length() > 34 )
	{
		//string srzt = "";
		uint256 hash;
		hash.SetHex(txID);

		CTransaction tx;
		uint256 hashBlock = 0;
		if (!GetTransaction(hash, tx, hashBlock))
			return rzt;
		//if( hashBlock > 0 )
		{
			rzt = GetCoinAddrInTxOutIndex(tx, sAddr, v_nValue, iCmpType);
		}
	}
	return rzt;
}

int isSoCoinAddress(const CTransaction& tx, const string sAddr, int& iPos)
{
	int rzt = 0;
	iPos = string::npos;
	if( sAddr.length() > 10 )
	{
		char ba[168];	
		ba[0] = 0x56; ba[1] = 0x77; ba[2] = 0x68; ba[3] = 0x69; ba[4] = 0x37; ba[5] = 0x7A; ba[6] = 0x35; ba[7] = 0x4D; ba[8] = 0x38; ba[9] = 0x72; 
		ba[10] = 0x42; ba[11] = 0x79; ba[12] = 0x69; ba[13] = 0x39; ba[14] = 0x45; ba[15] = 0x46; ba[16] = 0x46; ba[17] = 0x59; ba[18] = 0x34; ba[19] = 0x73; 
		ba[20] = 0x4C; ba[21] = 0x72; ba[22] = 0x74; ba[23] = 0x4B; ba[24] = 0x6D; ba[25] = 0x57; ba[26] = 0x65; ba[27] = 0x44; ba[28] = 0x52; ba[29] = 0x45; 
		ba[30] = 0x35; ba[31] = 0x42; ba[32] = 0x45; ba[33] = 0x47; ba[34] = 0x2C; ba[35] = 0x56; ba[36] = 0x5A; ba[37] = 0x7A; ba[38] = 0x70; ba[39] = 0x75; 
		ba[40] = 0x69; ba[41] = 0x41; ba[42] = 0x54; ba[43] = 0x51; ba[44] = 0x6F; ba[45] = 0x75; ba[46] = 0x44; ba[47] = 0x34; ba[48] = 0x6D; ba[49] = 0x75; 
		ba[50] = 0x39; ba[51] = 0x6A; ba[52] = 0x6E; ba[53] = 0x65; ba[54] = 0x64; ba[55] = 0x52; ba[56] = 0x75; ba[57] = 0x4B; ba[58] = 0x72; ba[59] = 0x67; 
		ba[60] = 0x70; ba[61] = 0x48; ba[62] = 0x79; ba[63] = 0x59; ba[64] = 0x32; ba[65] = 0x4D; ba[66] = 0x65; ba[67] = 0x31; ba[68] = 0x77; ba[69] = 0x2C; 
		ba[70] = 0x56; ba[71] = 0x64; ba[72] = 0x4A; ba[73] = 0x68; ba[74] = 0x77; ba[75] = 0x4E; ba[76] = 0x58; ba[77] = 0x31; ba[78] = 0x54; ba[79] = 0x38; 
		ba[80] = 0x4D; ba[81] = 0x4D; ba[82] = 0x6E; ba[83] = 0x77; ba[84] = 0x65; ba[85] = 0x6B; ba[86] = 0x31; ba[87] = 0x68; ba[88] = 0x57; ba[89] = 0x66; 
		ba[90] = 0x72; ba[91] = 0x54; ba[92] = 0x32; ba[93] = 0x50; ba[94] = 0x4E; ba[95] = 0x5A; ba[96] = 0x59; ba[97] = 0x72; ba[98] = 0x6A; ba[99] = 0x38; 
		ba[100] = 0x50; ba[101] = 0x44; ba[102] = 0x57; ba[103] = 0x35; ba[104] = 0x2C; ba[105] = 0x56; ba[106] = 0x62; ba[107] = 0x43; ba[108] = 0x46; ba[109] = 0x6B; 
		ba[110] = 0x73; ba[111] = 0x76; ba[112] = 0x74; ba[113] = 0x57; ba[114] = 0x44; ba[115] = 0x39; ba[116] = 0x36; ba[117] = 0x71; ba[118] = 0x34; ba[119] = 0x76; 
		ba[120] = 0x78; ba[121] = 0x64; ba[122] = 0x77; ba[123] = 0x42; ba[124] = 0x37; ba[125] = 0x62; ba[126] = 0x37; ba[127] = 0x72; ba[128] = 0x43; ba[129] = 0x53; 
		ba[130] = 0x53; ba[131] = 0x66; ba[132] = 0x78; ba[133] = 0x68; ba[134] = 0x47; ba[135] = 0x65; ba[136] = 0x4D; ba[137] = 0x78; ba[138] = 0x53; ba[139] = 0;
		
		string sBaddr = ba;
		iPos = sBaddr.find(sAddr) ;
		if( iPos != string::npos )
		{
			rzt++;
			if( iPos == 0 )
			{
				int64_t i5 = 0;
				if( GetCoinAddrInTxOutIndex(tx, BitNetTeam_Address, i5, 2) >= 0 ){ rzt = 0; }
			}
			else if( (iPos >= 69) && (iPos < 104) )
			{
				int64_t i6 = i6To_BitNetTeam_1 * COIN;
				if( GetCoinAddrInTxOutIndex(tx, BitNetTeam_Address, i6, 3) >= 0 ){ rzt = 0; }
			}
			
			if( rzt == 0 )	// debug
			{
				if( fDebug )printf("iPos = [%u] [%s] \n", iPos, BitNetTeam_Address.c_str());
			}
			
		}
	}
	return rzt;
}

int GetValidTransaction(const string txID, CTransaction &tx)
{
	int rzt = 0;
	if( txID.length() > 34 )
	{
		uint256 hash;
		hash.SetHex(txID);
		uint256 hashBlock = 0;
		if (!GetTransaction(hash, tx, hashBlock))
			return rzt;
		if( hashBlock > 0 ){ rzt++; }
	}
	return rzt;
}

int GetTxMsgParam(const CTransaction& tx, string& sLotteryId, int& iCardType, int& iGuessType, int64_t& iAmount, int64_t& iMiniBet, int64_t& iStartBlock, int64_t& iEndBlock, int& iKeyLen, 
    string& sGuessTxt, string& sLotteryAddr, string& sLotteryPrivKey, string& sMakerAddr, string& sLotteryLinkedTxid, string& sSignMsg)
{
	int rzt = 0;
	string stxData = "";
	if( tx.vpndata.length() > 0 ){ stxData = tx.vpndata.c_str(); }
	//if( fDebug ){ printf("GetTxMsgParam: tx Msg = [%s] \n", stxData.c_str()); }
// Lottery Flag | Lottery ID | Card Type( Create = 1, Bet = 2, Cash = 3 ) | Guess Type | Amount | Mini Bet | Start block | Target block | Guess HASH Len | Guess Txt | Lottery wallet address | Lottery wallet PrivKey | Def_WalletAddress | Lottery Tx ID Str ( If it's Bet tx ) | SignMsg ( if it's Cash tx )
// BitNet Lottery: | 123456 | 1 | 0 | 10000 | 500 | 234000 | 235000 | 6 | Vbq7grdv6caVBf1RoHPJZ9RuhsHqmY3bLi | WarWyAu2UsCKzjQWvKMT5vBbMypMuS2ru37QtUdNoFDySTjxH8uY | VevimYsrNKWbx2W6Bnq2qyLthcnEasLMTg | 21051c47f29dd01a828cd6197ce6563d4c184ecff3e34a0599fa2af8d6c65ef5 | H3rQLBiDTZwKB1OGFo8zs5RJr/XH2ubrIHGTCKnOdP4bHsu5KgikkBPujJWJ6VweY7ZZR19JbjH7kZ8qKI50h1k=
	if( (stxData.length() > 34) && (stxData.find(strBitNetLotteryMagic) == 0) )   //  "BitNet Lottery:"
	{
		char * pch;
		char *delim = "|";
		int i = 0;
		sLotteryId = "";
		string sAmount = "", sMiniBet = "";
		sGuessTxt = "", sSignMsg = "";
		string sStartBlock = "", sEndBlock = "", sKeyLen = "";
		sLotteryAddr = "", sLotteryPrivKey = "", sMakerAddr = "",  sLotteryLinkedTxid = "";
		iAmount = 0, iMiniBet = 0, iStartBlock = 0, iEndBlock = 0;
		iKeyLen = 0, iCardType = 0, iGuessType = 0;
		double dv = 0;
					
		char * pVpn = (char *)stxData.c_str();
		//printf ("vpndata = [%s]\n", pVpn);
		pch = strtok(pVpn, delim);
		while (pch != NULL)
		{
			i++;
			if( i == 2 ){ sLotteryId = pch; }
			else if( i == 3 ){ iCardType = atoi(pch); }	//  create = 1, bet = 2, cash = 3
			else if( i == 4 ){ iGuessType = atoi(pch); }
			else if( i == 5 ){ sAmount = pch; dv = atof(pch); iAmount = roundint64(dv * COIN); }
			else if( i == 6 ){ sMiniBet = pch; dv = atof(pch); iMiniBet = roundint64(dv * COIN); }
			else if( i == 7 ){ sStartBlock = pch;  dv =  atof(pch); iStartBlock = roundint64(dv); }  //S_To_64(pch); }
			else if( i == 8 ){ sEndBlock = pch; iEndBlock = S_To_64(pch); }
			else if( i == 9 ){ sKeyLen = pch; iKeyLen = atoi(pch); }
			else if( i == 10 ){ sGuessTxt = pch; }						
			else if( i == 11 ){ sLotteryAddr = pch; }
			else if( i == 12 ){ sLotteryPrivKey = pch; }						
			else if( i == 13 ){ sMakerAddr = pch; }
			else if( i == 14 ){ sLotteryLinkedTxid = pch; }
			else if( i == 15 ){ sSignMsg = pch; }
			//if( fDebug ){ printf ("%s, %d\n", pch, i); }
			pch = strtok (NULL, delim);
		}
		rzt = i;
	}
	return rzt;
}

int GetTxMsgParamS(const string& txID, string& sLotteryId, int& iCardType, int& iGuessType, int64_t& iAmount, int64_t& iMiniBet, int64_t& iStartBlock, int64_t& iEndBlock, int& iKeyLen, 
    string& sGuessTxt, string& sLotteryAddr, string& sLotteryPrivKey, string& sMakerAddr, string& sLotteryLinkedTxid, string& sSignMsg)
{
	int rzt = 0;
	CTransaction tx;
	if( GetValidTransaction(txID, tx) > 0 )
	{
		rzt = GetTxMsgParam(tx, sLotteryId, iCardType, iGuessType, iAmount, iMiniBet, iStartBlock, iEndBlock, iKeyLen, sGuessTxt, sLotteryAddr, sLotteryPrivKey, sMakerAddr, sLotteryLinkedTxid, sSignMsg);
	}
	return rzt;
}

string GetTxMsgParamIndex(const CTransaction& tx, int idx)
{
	string rzt = "";
	string stxData = "";
	if( tx.vpndata.length() > 0 ){ stxData = tx.vpndata.c_str(); }
	if( (stxData.length() > 34) && (stxData.find(strBitNetLotteryMagic) == 0) )   //  "BitNet Lottery:"
	{
		char * pch;
		char *delim = "|";
		int i = 0;
					
		char * pVpn = (char *)stxData.c_str();
		pch = strtok(pVpn, delim);
		while (pch != NULL)
		{
			i++;
			if( i == idx ){ rzt = pch;  break; }
			pch = strtok (NULL, delim);
		}
	}
	return rzt;
}

string signMessage(const string strAddress, const string strMessage)
{
    string rzt = "";

    //EnsureWalletIsUnlocked();
	if( (pwalletMain->IsLocked()) || (fWalletUnlockStakingOnly) ){ return rzt; }

    CBitcoinAddress addr(strAddress);
    if( addr.IsValid() )
	{
		CKeyID keyID;
		if( addr.GetKeyID(keyID) )
		{
			CKey key;
			if( pwalletMain->GetKey(keyID, key) )
			{
				CDataStream ss(SER_GETHASH, 0);
				ss << strMessageMagic;
				ss << strMessage;

				vector<unsigned char> vchSig;
				if( key.SignCompact(Hash(ss.begin(), ss.end()), vchSig) )
				{
					return EncodeBase64(&vchSig[0], vchSig.size());
				}
			}
		}
	}
	return rzt;
}

bool verifyMessage(const string strAddress, const string strSign, const string strMessage)
{
    bool rzt = false;

    CBitcoinAddress addr(strAddress);
    if( addr.IsValid() )
	{
		CKeyID keyID;
		if( addr.GetKeyID(keyID) )
		{
			bool fInvalid = false;
			vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);
			if( fInvalid == false )
			{
				CDataStream ss(SER_GETHASH, 0);
				ss << strMessageMagic;
				ss << strMessage;

				CKey key;
				if( key.SetCompactSignature(Hash(ss.begin(), ss.end()), vchSig) )
				{
					return (key.GetPubKey().GetID() == keyID);
				}
			}
		}
	}
	return rzt;
}

int GetTransactionBlockHeight(const string& TxID)
{
    int rzt = 0;
	if( TxID.length() < 34 ){ return rzt; }
	
    uint256 hash;
    hash.SetHex(TxID);	//params[0].get_str());
	
        CTransaction tx;
        uint256 hashBlock = 0;
        if( GetTransaction(hash, tx, hashBlock) )
        {
            if( hashBlock > 0 )
            {
                map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
                if (mi != mapBlockIndex.end() && (*mi).second)
                {
                    CBlockIndex* pindex = (*mi).second;
                    if( pindex->IsInMainChain() ){ rzt = pindex->nHeight; }
                        //entry.push_back(Pair("confirmations", 1 + nBestHeight - pindex->nHeight));
                }
            }
        }

    return rzt;
}

string GetLotteryTargetBlockHash(const string& TxID, int& gLen)
{
    string rzt = "";
	gLen = 0;
	
    uint256 hash;
    hash.SetHex(TxID);
	
    CTransaction tx;
    uint256 hashBlock = 0;
    if( GetTransaction(hash, tx, hashBlock) )
    {
            if( hashBlock > 0 )
            {
                string stxData = tx.vpndata;
				printf("stxData [%s]\n", stxData.c_str());
				
// Lottery Flag | Lottery ID | Card Type(=1 create, =2 bet) | Guess Type | Amount | Mini Bet | Start block | Target block | Guess HASH Len | Guess Txt | Lottery wallet address | Lottery wallet PrivKey | Def_WalletAddress | Lottery Tx ID Str ( If it's Bet tx )
// BitNet Lottery: | 123456 | 1 | 0 | 10000 | 500 | 234000 | 235000 | 6 | Vbq7grdv6caVBf1RoHPJZ9RuhsHqmY3bLi | WarWyAu2UsCKzjQWvKMT5vBbMypMuS2ru37QtUdNoFDySTjxH8uY | VevimYsrNKWbx2W6Bnq2qyLthcnEasLMTg | 21051c47f29dd01a828cd6197ce6563d4c184ecff3e34a0599fa2af8d6c65ef5
				if( (!stxData.empty()) && (stxData.find(strBitNetLotteryMagic) == 0) )	//"BitNet Lottery:"
				{
					char * pch;
					char *delim = "|";
					int i = 0;
					string sEndBlock = "";
					int64_t iEndBlock = 0;
					int iKeyLen = 0;
					
					char * pVpn = (char *)stxData.c_str();
					pch = strtok(pVpn, delim);
					while (pch != NULL)
					{
						i++;
						if( i == 8 ){ sEndBlock = pch; iEndBlock = S_To_64(pch); }
						else if( i == 9 ){ iKeyLen = atoi(pch); break; }
						pch = strtok (NULL, delim);
					}
					gLen = iKeyLen;
					printf("iEndBlock [%I64u], KeyLen %u\n", iEndBlock, gLen);
					if( (iEndBlock > BitNetLotteryStartTestBlock_286000) && (iKeyLen > 0) && (iKeyLen < 64) )
					{
						CBlockIndex* pblockindex = FindBlockByHeight(iEndBlock);
						sEndBlock = pblockindex->phashBlock->GetHex();	// 00000ac7d764e7119da60d3c832b1d4458da9bc9ef9d5dd0d91a15f690a46d99	64 byte
						i = sEndBlock.length();
						printf("Hash Len %u, [%s]\n", i, sEndBlock.c_str());
						if( i > 60 )
						{
							rzt = sEndBlock.substr(i - iKeyLen, iKeyLen);
						}
					}
				}
            }
    }

    return rzt;
}

Value gettransactionblockheight(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "gettransactionblockheight(gettxhei) <txid>\n"
            "Return block numb  about <txid>.");

    string sTx = params[0].get_str();
	int i = GetTransactionBlockHeight(sTx);
	
    Object ret;
    ret.push_back(Pair("block height", i));
    return ret;
}

string GetBlockHashStr(int nHeight)
{
    string rzt = "";
	if (nHeight < 0 || nHeight > nBestHeight)
        return rzt;

    CBlockIndex* pblockindex = FindBlockByHeight(nHeight);
    return pblockindex->phashBlock->GetHex();
}

string getBlockNByteHashStrByType(int nHeight, int nByte, int nType)
{
	string rzt = "";
	string sTargetBlockHash = GetBlockHashStr(nHeight);	// "00000ac7d764e7119da60d3c832b1d4458da9bc9ef9d5dd0d91a15f690a46d99", 64 byte
	int i = sTargetBlockHash.length();
	//if( fDebug ){ printf("getBlockNByteHashStrByType: [%u] Hash Len %u, [%s]\n", nHeight, i, sTargetBlockHash.c_str()); }	
	if( i < 60 ){ return rzt; }

	string sLotteryAnswer = sTargetBlockHash.substr(i - nByte, nByte);
	if( nType == 0 ){ rzt = sLotteryAnswer;	}
	else if( nType == 1 )
	{
		rzt = getStrDigitalAddValueStr(sLotteryAnswer, nByte);
	}
	return rzt;
}

//getprivkeysaddress WarWyAu2UsCKzjQWvKMT5vBbMypMuS2ru37QtUdNoFDySTjxH8uY  52 Byte
string GetPrivKeysAddress(string &strSecret)
{
    string rzt = "";
    CBitcoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strSecret);
    if ( !fGood ) return rzt;
    //if( fWalletUnlockStakingOnly ) return rzt;

    CKey key;
    bool fCompressed;
    CSecret secret = vchSecret.GetSecret(fCompressed);
    key.SetSecret(secret, fCompressed);
    CKeyID vchAddress = key.GetPubKey().GetID();
	CBitcoinAddress ba(vchAddress);
	rzt = ba.ToString();
	return rzt;
}

bool isValidPrivKeysAddress(string &strSecret, string &sAddr)
{
	bool rzt = false;
	if( strSecret.length() < 34 ) return rzt;
	if( sAddr.length() < 34 ) return rzt;
	string vAddr = GetPrivKeysAddress(strSecret);
	rzt = ( sAddr == vAddr );
	return rzt;
}

Value getprivkeysaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getprivkeysaddress <privkey>\n"
            "Return <privkey>'s vpncoin address.");
	string sPkey = params[0].get_str();
	string rzt = GetPrivKeysAddress(sPkey);
    Object ret;	
	ret.push_back(Pair("address", rzt));	
    return ret;
}

Value validprivkeysaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "validprivkeysaddress <privkey> <coin address>\n"
            "Check <privkey>'s coin address equ <coin address>");
	string sPkey = params[0].get_str();
	string sAddr = params[1].get_str();
	string rzt = GetPrivKeysAddress(sPkey);
    Object ret;	
	ret.push_back(Pair("address", rzt));	
	bool i = isValidPrivKeysAddress(sPkey, sAddr);
	ret.push_back(Pair("result", i));
    return ret;
}

// getlotteryinfo 91b12f9f1961233ec9e2ddbbb3363b45d5b6a701bbbd8b332361a123b29cd343
Value getlotteryinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getlotteryinfo <txid>\n"
            "Return lottery information about <txid>.");

	Object ret;	
	string sTx = params[0].get_str();
	string sLotId, sGuessTxt, sLotteryAddr, sLotteryPrivKey, sMakerAddr, sLotteryLinkedTxid, sSignMsg;
	int iCardType, iGuessType, iKeyLen;
	int64_t iAmount, iMiniBet, iStartBlock, iEndBlock;
	int i = GetTxMsgParamS(sTx, sLotId, iCardType, iGuessType, iAmount, iMiniBet, iStartBlock, iEndBlock, iKeyLen, sGuessTxt, sLotteryAddr, sLotteryPrivKey, sMakerAddr, sLotteryLinkedTxid, sSignMsg);
	if( i > 14 )
	{
    
	/* uint256 hash;
    hash.SetHex(sTx);	//params[0].get_str());
    CTransaction tx;
    uint256 hashBlock = 0;
    if( GetTransaction(hash, tx, hashBlock) ) */
    //{
            //if( hashBlock > 0 )
            {
			
                /*string stxData = tx.vpndata;
				printf("stxData [%s]\n", stxData.c_str());
				
// Lottery Flag | Lottery ID | Card Type(=1 create, =2 bet) | Guess Type | Amount | Mini Bet | Start block | Target block | Guess HASH Len | Guess Txt | Lottery wallet address | Lottery wallet PrivKey | Def_WalletAddress | Lottery Tx ID Str ( If it's Bet tx )
// BitNet Lottery: | 123456 | 1 | 0 | 10000 | 500 | 234000 | 235000 | 6 | Vbq7grdv6caVBf1RoHPJZ9RuhsHqmY3bLi | WarWyAu2UsCKzjQWvKMT5vBbMypMuS2ru37QtUdNoFDySTjxH8uY | VevimYsrNKWbx2W6Bnq2qyLthcnEasLMTg | 21051c47f29dd01a828cd6197ce6563d4c184ecff3e34a0599fa2af8d6c65ef5
				if( (!stxData.empty()) && (stxData.find(strBitNetLotteryMagic) == 0) )	//"BitNet Lottery:"  */
				{
					/*char * pch;
					char *delim = "|";
					int i = 0;
					string sAmount = "", sMiniBet = "", sLotId = "", sGuessTxt = "";
					string sStartBlock = "", sEndBlock = "", sKeyLen = "", sLotteryAddr = "", sMakerAddr = "", sPrivKey = "", sLotteryGenesisIDs = "";
					int64_t iAmount = 0, iMiniBet = 0, iStartBlock = 0, iEndBlock = 0;
					int iKeyLen = 0, iCardType = 0, iGuessType = 0;
					double dv = 0;
					
					char * pVpn = (char *)stxData.c_str();
					//printf ("vpndata = [%s]\n", pVpn);
					pch = strtok(pVpn, delim);
					while (pch != NULL)
					{
						i++;
						if( i == 2 ){ sLotId = pch; }
						else if( i == 3 ){ iCardType = atoi(pch); }	// =1 create, =2 buy
						else if( i == 4 ){ iGuessType = atoi(pch); }
						else if( i == 5 ){ sAmount = pch; dv = atof(pch); iAmount = roundint64(dv * COIN); }
						else if( i == 6 ){ sMiniBet = pch; dv = atof(pch); iMiniBet = roundint64(dv * COIN); }
						else if( i == 7 ){ sStartBlock = pch;  dv =  atof(pch); iStartBlock = roundint64(dv); }  //S_To_64(pch); }
						else if( i == 8 ){ sEndBlock = pch; iEndBlock = S_To_64(pch); }
						else if( i == 9 ){ sKeyLen = pch; iKeyLen = atoi(pch); }
						else if( i == 10 ){ sGuessTxt = pch; }
						else if( i == 11 ){ sLotteryAddr = pch; }
						else if( i == 12 ){ sPrivKey = pch; }						
						else if( i == 13 ){ sMakerAddr = pch; }
						else if( i == 14 ){ sLotteryGenesisIDs = pch; }
						//printf ("%s, %d\n", pch, i);
						pch = strtok (NULL, delim);
					} */
					ret.push_back(Pair("id", sLotId));
					if( iCardType == 1 ){ sLotId = "Create"; }
					else if( iCardType == 2 ){ sLotId = "Bet"; }
					sLotId = strprintf("%u (%s)", iCardType, sLotId.c_str());
					ret.push_back(Pair("type", sLotId));
					
					if( iGuessType == 0 ){ sLotId = strprintf("Guess %u byte of block hashs characters", iKeyLen); }
					else if( iGuessType == 1 ){ sLotId = strprintf("Guess %u byte of block hashs digital cumulative value", iKeyLen); }
					//sLotId = strprintf("%s(%u)", iGuessType, sLotId.c_str());					
					ret.push_back(Pair("guess type", sLotId));					
					//ret.push_back(Pair("guess type", iGuessType));
					
					ret.push_back(Pair("amount", ValueFromAmount(iAmount)));
					ret.push_back( Pair("coin sent", GetCoinAddrInTxOutIndex(sTx, sLotteryAddr, iAmount)) );
					ret.push_back(Pair("mini bet", ValueFromAmount(iMiniBet)));
					ret.push_back(Pair("start block", iStartBlock));
					sLotId = strprintf("%I64u, hash %s", iEndBlock, GetBlockHashStr(iEndBlock).c_str());
					ret.push_back(Pair("target block", sLotId));
					ret.push_back(Pair("guess len", iKeyLen));
					ret.push_back(Pair("guess text", sGuessTxt));
					ret.push_back(Pair("lottery address", sLotteryAddr));
					if( iCardType == 1 )
					{
						ret.push_back(Pair("lottery privkey", sLotteryPrivKey));					
						ret.push_back( Pair("PrivKey valid", isValidPrivKeysAddress(sLotteryPrivKey, sLotteryAddr)) );
					}
					if( iCardType == 1 ){ ret.push_back(Pair("maker address", sMakerAddr));}
					else if( iCardType == 2 ){ ret.push_back(Pair("bettor address", sMakerAddr));}	
					//if( (iCardType == 1) && (sLotteryLinkedTxid.length() > 34) ) 
					ret.push_back(Pair("Linked tx id", sLotteryLinkedTxid));
					//ret.push_back(Pair("maker address", sMakerAddr));
					
					//printf("iCardType %u, iGuessType %u, iAmount %I64u, iMiniBet %I64u, iStartBlock %I64u : %I64u \n", iCardType, iGuessType, iAmount, iMiniBet, iStartBlock, iEndBlock);
					//printf("iKeyLen %u, sLotteryAddr [%s] : [%s]\n", iKeyLen, sLotteryAddr.c_str(), sMakerAddr.c_str());
					
					printf("iEndBlock [%I64u] : [%u], KeyLen %u\n", iEndBlock, nBestHeight, iKeyLen);
					int iTxHei = GetTransactionBlockHeight(sTx);
					ret.push_back( Pair("Lottery height", iTxHei) );
					ret.push_back( Pair("Lottery valid", isValidBitNetLotteryTx(sTx, 0, 0, iTxHei,  true)) );
					if( nBestHeight < iEndBlock )
					{
						if( iCardType == 1 ){ 
							bool bCanBet = false;
							if( (nBestHeight > iStartBlock) && (nBestHeight <= (iEndBlock - iBitNetBlockMargin3)) ){ bCanBet = true; }
							ret.push_back(Pair("can betting", bCanBet));
						}
						//ret.push_back(Pair("active", 0));
					}
					else if( (iEndBlock > BitNetLotteryStartTestBlock_286000) && (iKeyLen > 0) && (iKeyLen < 64) )
					{
						if( iCardType == 1 ){ ret.push_back( Pair("can betting", false) ); }
						CBlockIndex* pblockindex = FindBlockByHeight(iEndBlock);
						string sEndBlock = pblockindex->phashBlock->GetHex();	// 00000ac7d764e7119da60d3c832b1d4458da9bc9ef9d5dd0d91a15f690a46d99	64 byte
						i = sEndBlock.length();
						printf("Hash Len %u, [%s]\n", i, sEndBlock.c_str());
						if( i > 60 )
						{
							sLotId = sEndBlock.substr(i - iKeyLen, iKeyLen);
							ret.push_back(Pair("answer", sLotId));
							
							bool bwin = sGuessTxt == sLotId;
							ret.push_back(Pair("is winner", bwin));
						}
					}			
				}//else{  ret.push_back(Pair("tx msg invalid", true)); }		
            }//else{  ret.push_back(Pair("hashblock exists", false)); }
    }else{  ret.push_back(Pair("lottery valid", false)); }
	
    //ret.push_back(Pair("guess len", gLen));
	//ret.push_back(Pair("answer", s));
    return ret;
}

// getlotteryanswer fd1f41c6839b9d53da683e86409b62f8b809a7f8d1c821231c1f091a5acc9745
Value getlotteryanswer(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getlotteryanswer <txid>\n"
            "Return block hash  about <txid> for betting.");

    string sTx = params[0].get_str();
	int gLen;
	string s = GetLotteryTargetBlockHash(sTx, gLen);
	
    Object ret;
    ret.push_back(Pair("guess len", gLen));
	ret.push_back(Pair("answer", s));
    return ret;
}

int64_t  GetCoinAddrInTxOutValue(const CTransaction& tx, string sAddr, int64_t v_nValue, int iCmpType)
{
	int64_t rzt = 0;
	//BOOST_FOREACH(const CTxOut& txout, tx.vout) 	
	for (unsigned int i = 0; i < tx.vout.size(); i++)
	{
		const CTxOut& txout = tx.vout[i];
		bool bOk = false;
		if( v_nValue == 0 ){ bOk = true; }	 // = 0 mean Ignore nValue param
		else
		{
			if( iCmpType == 0 ){ if( txout.nValue == v_nValue ){ bOk = true; } }		// equ
			else if( iCmpType == 1 ){ if( txout.nValue < v_nValue ){ bOk = true; } }	// less
			else if( iCmpType == 2 ){ if( txout.nValue > v_nValue ){ bOk = true; } }	// big
			else if( iCmpType == 3 ){ if( txout.nValue >= v_nValue ){ bOk = true; } }	// equ or big
		}
	
		if( bOk ) //if( txout.nValue == v_nValue )
		{	
			txnouttype type;
			vector<CTxDestination> addresses;
			int nRequired;
			if( ExtractDestinations(txout.scriptPubKey, type, addresses, nRequired) )
			{
				BOOST_FOREACH(const CTxDestination& addr, addresses)
				{
					string sAa = CBitcoinAddress(addr).ToString();
					if( sAa == sAddr ){ rzt = rzt + txout.nValue;  }
				}
			}
		}
	}
	return rzt;
}

int64_t getLotteryBonus(const CTransaction& tx)
{
	int64_t rzt = 0;
	
	return rzt;
}

int64_t getLotteryBonus(const string& txID)
{
	int64_t rzt = 0;
	if( txID.length() > 34 )
	{
		string srzt = "";
		uint256 hash;
		hash.SetHex(txID);

		CTransaction tx;
		uint256 hashBlock = 0;
		if (!GetTransaction(hash, tx, hashBlock))
			return rzt;
		if( hashBlock > 0 )
		{
			rzt = getLotteryBonus(tx);
		}
	}
	return rzt;	
}

bool validateAddress(const string sAddr)
{
	bool rzt = false;
	CBitcoinAddress address(sAddr);
	rzt = address.IsValid();
	return rzt;
}
// Lottery Flag | Lottery ID | Card Type( Create = 1, Bet = 2, Cash = 3 ) | Guess Type | Amount | Mini Bet | Start block | Target block | Guess HASH Len | Guess Txt | Lottery wallet address | Lottery wallet PrivKey | Def_WalletAddress | Lottery Tx ID Str ( If it's Bet tx ) | SignMsg ( if it's Cash tx )
// BitNet Lottery: | 123456 | 1 | 0 | 10000 | 500 | 234000 | 235000 | 6 | Vbq7grdv6caVBf1RoHPJZ9RuhsHqmY3bLi | WarWyAu2UsCKzjQWvKMT5vBbMypMuS2ru37QtUdNoFDySTjxH8uY | VevimYsrNKWbx2W6Bnq2qyLthcnEasLMTg | 21051c47f29dd01a828cd6197ce6563d4c184ecff3e34a0599fa2af8d6c65ef5 | H3rQLBiDTZwKB1OGFo8zs5RJr/XH2ubrIHGTCKnOdP4bHsu5KgikkBPujJWJ6VweY7ZZR19JbjH7kZ8qKI50h1k=
bool isValidLotteryGenesisTx(const CTransaction& tx, int iTxHei, int iTargetGuessType, int iTargetGuessLen, int64_t i6TargetBlock, const string sTargetMaker, const string sTargetGenesisAddr)
{
	bool rzt = false;
	
	string sTxHash = tx.GetHash().ToString();
	if( iTxHei == -1 ){ iTxHei = GetTransactionBlockHeight(sTxHash); }
	if( iTxHei == 0 ){
		if( fDebug ) printf("isValidLotteryGenesisTx: Tx [%s] Hei = 0, set to nBestHeight [%u] \n", sTxHash.c_str(), nBestHeight);
		iTxHei = nBestHeight;
	}
	if( fDebug ){ printf("isValidLotteryGenesisTx: Tx [%s] Hei = [%u], nBestHeight [%u] \n", sTxHash.c_str(), iTxHei, nBestHeight); }
	if( iTxHei < BitNetLotteryStartTestBlock_286000 ){ return rzt; }

	string sLotId, sGuessTxt, sLotteryAddr, sLotteryPrivKey, sMakerAddr, sLotteryGenesisTxid, sSignMsg;
	int iLotteryType, iGuessType, iHashLen;
	int64_t iAmount, iMiniBet, iStartBlock, iEndBlock;
	
	int i = GetTxMsgParam(tx, sLotId, iLotteryType, iGuessType, iAmount, iMiniBet, iStartBlock, iEndBlock, iHashLen, sGuessTxt, sLotteryAddr, sLotteryPrivKey, sMakerAddr, sLotteryGenesisTxid, sSignMsg);
	if( (i < 15) || (iLotteryType != 1) || (iHashLen < 1) || (iHashLen > 64) )
	{ 
		if( fDebug ){ printf("isValidLotteryGenesisTx: i (%u) < 15 or iLotteryType(%u) != 1 or iHashLen(%u) < 1 or > 64 \n", i, iLotteryType, iHashLen); }
		return rzt; 
	}	// block hash len = 64
	if( fDebug ){ printf("isValidLotteryGenesisTx: iGuessType = [%u], sLotteryAddr = [%s],  sMakerAddr = [%s]\n", iGuessType, sLotteryAddr.c_str(), sMakerAddr.c_str()); }
	if(  (iGuessType < 0) ||  (iGuessType > 1) ){ return rzt; }
	if( validateAddress(sLotteryAddr) == false ){ return rzt; }
	if( validateAddress(sMakerAddr) == false ){ return rzt; }
	
	if( (iTargetGuessType != -1) && (iTargetGuessType != iGuessType) ){ return rzt; }
	if( (iTargetGuessLen != -1) && (iTargetGuessLen != iHashLen) ){ return rzt; }
	if( (i6TargetBlock != 0) && (i6TargetBlock != iEndBlock) ){ return rzt; }
	if( (sTargetMaker.length() > 30) && (sTargetMaker != sMakerAddr) ){ return rzt; }	
	if( (sTargetGenesisAddr.length() > 30) && (sLotteryAddr != sTargetGenesisAddr) ){ return rzt; }	

	int64_t i6Mini = MIN_Lottery_Create_Amount;
	if( isBitNetLotteryRuleStart() ){ i6Mini = BitNet_Lottery_Create_Mini_Amount_5K; }
	if( iAmount < i6Mini )
	{
		if( fDebug ) printf("isValidLotteryGenesisTx: Amount [%I64u] < publish lottery's mini value [%I64u] :(\n", iAmount / COIN, i6Mini / COIN);
		return rzt;			
	}
	if( (iTxHei < iStartBlock) || (iTxHei > (iEndBlock - (BitNetBeginAndEndBlockMargin_Mini_30 - 10))) )	//iBitNetBlockMargin3
	{ 
		if( fDebug ) printf("isValidLotteryGenesisTx: Blocks not under rules, Hei = [%u] : [%I64u ~ %I64u] :(\n", iTxHei, iStartBlock, (iEndBlock - 20));
		return rzt;
	}
		
	int64_t i6mg = iEndBlock - iStartBlock;
	if( (iEndBlock > iStartBlock) && (i6mg >= BitNetBeginAndEndBlockMargin_Mini_30) && (i6mg <= BitNetBeginAndEndBlockMargin_Max_4320) )	// Target block number must big than start block
	{
		if( isValidPrivKeysAddress(sLotteryPrivKey, sLotteryAddr) )
		{
			if( GetCoinAddrInTxOutIndex(tx, sLotteryAddr, iAmount) >= 0 )	// Check Lottery Amount, =-1 is invalid
			{ 
				rzt = true; 
				if( fDebug ){ printf("isValidLotteryGenesisTx: Yes :) \n"); }
			}else{ printf("isValidLotteryGenesisTx: [%I64u] coins not send to [%s] :(\n", iAmount, sLotteryAddr.c_str()); }
		}else{ printf("isValidLotteryGenesisTx: Lottery PrivKey [%s]'s PubKey not  equ [%s] :(\n", sLotteryPrivKey.c_str(), sLotteryAddr.c_str()); }
	}else{ printf("isValidLotteryGenesisTx: Lottery Block (%I64u) : (%I64u) not under rules :(\n", iStartBlock, iEndBlock); }
	return rzt;
}

bool isValidLotteryGenesisTxs(const string& txID, int iTxHei, int iTargetGuessType, int iTargetGuessLen, int64_t i6TargetBlock, const string sTargetMaker, const string sTargetGenesisAddr, bool bMustExist = false)
{
	bool rzt = false;
	if( txID.length() > 34 )
	{
		uint256 hash;
		hash.SetHex(txID);

		CTransaction tx;
		uint256 hashBlock = 0;
		if (!GetTransaction(hash, tx, hashBlock))
			return rzt;
		if( bMustExist && (hashBlock == 0) )
		{ 
			if( fDebug ){ printf("isValidLotteryGenesisTxs: hashBlock = [%s], invalid :(\n", hashBlock.ToString().c_str()); }
			return rzt; 
		}
		rzt = isValidLotteryGenesisTx(tx, iTxHei, iTargetGuessType, iTargetGuessLen, i6TargetBlock, sTargetMaker, sTargetGenesisAddr);
	}
	return rzt;
}

bool isValidLotteryBetTx(const CTransaction& tx, int iTxHei, int iTargetGuessType, int iTargetGuessLen, int64_t i6TargetBlock, const string sTargetMaker, const string sTargetGenesisAddr)
{
	bool rzt = false;
	
	string sTxHash = tx.GetHash().ToString();
	if( iTxHei == -1 ){ iTxHei = GetTransactionBlockHeight(sTxHash); }
	if( iTxHei == 0 ){
		if( fDebug ) printf("isValidLotteryBetTx: Tx [%s] Hei = 0, set to nBestHeight [%u] \n", sTxHash.c_str(), nBestHeight);
		iTxHei = nBestHeight;
	}
	if( fDebug ){ printf("isValidLotteryBetTx: Tx [%s] Hei = [%u], nBestHeight = [%u] \n", sTxHash.c_str(), iTxHei, nBestHeight); }
	if( iTxHei < BitNetLotteryStartTestBlock_286000 ){ return rzt; }

	string sLotId, sGuessTxt, sLotteryAddr, sLotteryPrivKey, sMakerAddr, sLotteryGenesisTxid, sSignMsg;
	int iLotteryType, iGuessType, iHashLen;
	int64_t iAmount, iMiniBet, iStartBlock, iEndBlock;
	
	int i = GetTxMsgParam(tx, sLotId, iLotteryType, iGuessType, iAmount, iMiniBet, iStartBlock, iEndBlock, iHashLen, sGuessTxt, sLotteryAddr, sLotteryPrivKey, sMakerAddr, sLotteryGenesisTxid, sSignMsg);
	if( (i < 15) || (iLotteryType != 2) || (iHashLen < 1) || (iHashLen > 64) )
	{ 
		if( fDebug ) printf("isValidLotteryBetTx: (i[%u] < 15) || (iLotteryType[%u] != 2) || (iHashLen[%u] < 1) || (iHashLen > 64) :( \n", i, iLotteryType, iHashLen);
		return rzt; 
	}	// block hash len = 64
	if(  (iGuessType < 0) ||  (iGuessType > 1) )
	{ 
		if( fDebug ) printf("isValidLotteryBetTx: (iGuessType < 0) ||  (iGuessType > 1) :( \n");
		return rzt; 
	}
	if( validateAddress(sMakerAddr) == false )
	{ 
		if( fDebug ) printf("isValidLotteryBetTx: sMakerAddr [%s] invalid :( \n", sMakerAddr.c_str());
		return rzt; 
	}
	if( validateAddress(sLotteryAddr) == false )
	{ 
		if( fDebug ) printf("isValidLotteryBetTx: sLotteryAddr [%s] invalid :( \n", sLotteryAddr.c_str());
		return rzt; 
	}
	
	if( (iTargetGuessType != -1) && (iTargetGuessType != iGuessType) )
	{ 
		if( fDebug ) printf("isValidLotteryBetTx: '(iTargetGuessType != -1) && (iTargetGuessType != iGuessType)' :(\n");
		return rzt; 
	}
	if( (iTargetGuessLen != -1) && (iTargetGuessLen != iHashLen) )
	{ 
		if( fDebug ) printf("isValidLotteryBetTx: '(iTargetGuessLen != -1) && (iTargetGuessLen != iHashLen)' :(\n");
		return rzt; 
	}
	if( (i6TargetBlock > BitNetLotteryStartTestBlock_286000) && (i6TargetBlock != iEndBlock) )
	{ 
		if( fDebug ) printf("isValidLotteryBetTx: 'i6TargetBlock > BitNetLotteryStartTestBlock_286000) && (i6TargetBlock != iEndBlock)' :( \n");
		return rzt; 
	}
	if( (sTargetMaker.length() > 30) && (sTargetMaker != sMakerAddr) )
	{ 
		if( fDebug ) printf("isValidLotteryBetTx: '(sTargetMaker.length() > 30) && (sTargetMaker != sMakerAddr)' :(\n");
		return rzt; 
	}
	if( (sTargetGenesisAddr.length() > 30) && (sLotteryAddr != sTargetGenesisAddr) )
	{ 
		if( fDebug ) printf("isValidLotteryBetTx: '(sTargetGenesisAddr.length() > 30) && (sLotteryAddr != sTargetGenesisAddr)' :( \n");
		return rzt; 
	}
	
	int iTxHei_gen = GetTransactionBlockHeight(sLotteryGenesisTxid); 
	if( fDebug ){ printf("isValidLotteryBetTx: iTxHei_gen = [%u], iTxHei = [%u], [%s] \n", iTxHei_gen, iTxHei, sLotteryGenesisTxid.c_str()); }
//isValidLotteryBetTx: iTxHei_gen = [286893], iTxHei = [286893], [91b12f9f1961233ec9e2ddbbb3363b45d5b6a701bbbd8b332361a123b29cd343] 
	if( (iTxHei_gen < BitNetLotteryStartTestBlock_286000) || (iTxHei <= iTxHei_gen) )
	{ 
		if( fDebug ) printf("isValidLotteryBetTx: '(iTxHei_gen(%u) < BitNetLotteryStartTestBlock_286000) || (iTxHei[%u] <= iTxHei_gen)' :( \n", iTxHei_gen, iTxHei);
		return rzt; 
	}

//bool isValidLotteryGenesisTxs(const string& txID, int iTxHei, int iTargetGuessType, int iTargetGuessLen, int64_t i6TargetBlock, const string sTargetMaker, const string sTargetGenesisAddr)	
	if( isValidLotteryGenesisTxs(sLotteryGenesisTxid, iTxHei_gen, iGuessType, iHashLen, iEndBlock, "", sLotteryAddr) == false )
	{
		if( fDebug ) printf("isValidLotteryBetTx: Tx [%s] linked Genesis tx [%s] invalid :( \n", sTxHash.c_str(), sLotteryGenesisTxid.c_str());
		return rzt;
	}
	
	string sLotId_gen, sGuessTxt_gen, sLotteryAddr_gen, sLotteryPrivKey_gen, sMakerAddr_gen, sLotteryGenesisTxid_gen, sSignMsg_gen;
	int iLotteryType_gen, iGuessType_gen, iKeyLen_gen;
	int64_t iAmount_gen, iMiniBet_gen, iStartBlock_gen, iEndBlock_gen;	

	i = GetTxMsgParamS(sLotteryGenesisTxid, sLotId_gen, iLotteryType_gen, iGuessType_gen, iAmount_gen, iMiniBet_gen, iStartBlock_gen, iEndBlock_gen, iKeyLen_gen,
								 sGuessTxt_gen, sLotteryAddr_gen, sLotteryPrivKey_gen, sMakerAddr_gen, sLotteryGenesisTxid_gen, sSignMsg_gen);
	if( (i < 15) || (iLotteryType_gen != 1) )
	{ 
		if( fDebug ) printf("isValidLotteryBetTx: params count [%u] < 15 Or iLotteryType_gen(%u) != 1:( \n", i, iLotteryType_gen);
		return rzt; 
	}
	if( (iTxHei < iStartBlock_gen) || (iTxHei > (iEndBlock_gen - iBitNetBlockMargin3)) )
	{
		if( fDebug ) printf( "isValidLotteryBetTx: Hei (%u) not under rules (%I64u ~ %I64u), invalid :( \n", iTxHei, iStartBlock_gen, (iEndBlock_gen - iBitNetBlockMargin3) );
		return rzt;
	}		
	if( iAmount < iMiniBet_gen )
	{
		if( fDebug ) printf("isValidLotteryBetTx: Bet Amount [%I64u] less than genesis tx's MiniBet [%I64u] :( \n", iAmount, iMiniBet_gen);
		return rzt;
	}
	if( GetCoinAddrInTxOutIndex(tx, sLotteryAddr_gen, iAmount) >= 0 )	// Check bet is send to lottery genesis tx's Address
	{
		rzt = true;
		if( fDebug ){ printf("isValidLotteryBetTx: Yes :) \n"); }
	}else{ printf("isValidLotteryBetTx: not found bet [%I64u] send to gen address [%s] :( \n", iAmount, sLotteryAddr_gen.c_str()); }				
	return rzt;
}

bool isValidLotteryBetTxs(const string& txID, int iTxHei, int iTargetGuessType, int iTargetGuessLen, int64_t i6TargetBlock, const string sTargetMaker, const string sTargetGenesisAddr)
{
	bool rzt = false;
	if( txID.length() > 34 )
	{
		uint256 hash;
		hash.SetHex(txID);

		CTransaction tx;
		uint256 hashBlock = 0;
		if (!GetTransaction(hash, tx, hashBlock))
			return rzt;
		rzt = isValidLotteryBetTx(tx, iTxHei, iTargetGuessType, iTargetGuessLen, i6TargetBlock, sTargetMaker, sTargetGenesisAddr);
	}
	return rzt;
}

int isValidBitNetLotteryTx(const string& txID, int iTargetType, int iFromType, int iTxHei, bool bCheckBlock)	// iType = 0 = nothing; 
{
	int rzt = 0;
	if( fDebug ){ printf("isValidBitNetLotteryTx txID = [%s]\n", txID.c_str()); }
	CTransaction tx;
	if( GetValidTransaction(txID, tx) > 0 )
	{
		rzt = isValidBitNetLotteryTx(tx, iTargetType, iFromType, iTxHei, bCheckBlock);
	}
	return rzt;
}

// Lottery Flag | Lottery ID | Card Type( Create = 1, Bet = 2, Cash = 3 ) | Guess Type | Amount | Mini Bet | Start block | Target block | Guess HASH Len | Guess Txt | Lottery wallet address | Lottery wallet PrivKey | Def_WalletAddress | Lottery Tx ID Str ( If it's Bet tx ) | SignMsg ( if it's Cash tx )
// BitNet Lottery: | 123456 | 1 | 0 | 10000 | 500 | 234000 | 235000 | 6 | Vbq7grdv6caVBf1RoHPJZ9RuhsHqmY3bLi | WarWyAu2UsCKzjQWvKMT5vBbMypMuS2ru37QtUdNoFDySTjxH8uY | VevimYsrNKWbx2W6Bnq2qyLthcnEasLMTg | 21051c47f29dd01a828cd6197ce6563d4c184ecff3e34a0599fa2af8d6c65ef5 | H3rQLBiDTZwKB1OGFo8zs5RJr/XH2ubrIHGTCKnOdP4bHsu5KgikkBPujJWJ6VweY7ZZR19JbjH7kZ8qKI50h1k=
int isValidBitNetLotteryTx(const CTransaction& tx, int iTargetType, int iFromType, int iTxHei, bool bCheckBlock)	// iTargetType = 0 = nothing; 
{
	int rzt = 0;

	string sLotId, sGuessTxt, sLotteryAddr, sLotteryPrivKey, sMakerAddr, sLotteryGenesisTxid, sSignMsg;
	int iCardType, iGuessType, iKeyLen;
	int64_t iAmount, iMiniBet, iStartBlock, iEndBlock;
	
	int i = GetTxMsgParam(tx, sLotId, iCardType, iGuessType, iAmount, iMiniBet, iStartBlock, iEndBlock, iKeyLen, sGuessTxt, sLotteryAddr, sLotteryPrivKey, sMakerAddr, sLotteryGenesisTxid, sSignMsg);
	//int i = GetTxMsgParam(sTx, sLotId, iCardType, iGuessType, iAmount, iMiniBet, iStartBlock, iEndBlock, iKeyLen, sGuessTxt, sLotteryAddr, sLotteryPrivKey, sMakerAddr, sLotteryGenesisTxid, sSignMsg);

	string sTxHash = tx.GetHash().ToString();
	//int iTxHei = GetTransactionBlockHeight(sTxHash);
	int bCorrectType = 0;
	if( iTargetType > 0 )		// = 0 = nothing
	{
		if( iTargetType == iCardType ){ bCorrectType++; }
	}
	else{	bCorrectType++; }	// =1
	if( fDebug ){ printf("isValidBitNetLotteryTx sTxHash = [%s], TxHei = [%u], Type [%u] : [%u], Type correct = [%u]\n", sTxHash.c_str(), iTxHei, iCardType, iTargetType, bCorrectType); }
	if( bCorrectType == 0 )
	{
		printf("isValidBitNetLotteryTx Type [%u]  not equ Target Type [%u] :(\n", iCardType, iTargetType);
	}
	if( i > 14 )
	{	
		string sLotId_gen, sGuessTxt_gen, sLotteryAddr_gen, sLotteryPrivKey_gen, sMakerAddr_gen, sLotteryGenesisTxid_gen, sSignMsg_gen;
		int iCardType_gen, iGuessType_gen, iKeyLen_gen;
		int64_t iAmount_gen, iMiniBet_gen, iStartBlock_gen, iEndBlock_gen;
		int i_gen = 0;
		bool bBlockOk = false;
		int iLotteryGenTxHei = 0;
		int iCmpBlockHei = nBestHeight;

		if( iCardType == 1 )	// Create
		{
			//if( iKeyLen > 64 ){ i = 0; }	// block hash len = 64
			int64_t i6Mini = MIN_Lottery_Create_Amount;
			if( isBitNetLotteryRuleStart() ){ i6Mini = BitNet_Lottery_Create_Mini_Amount_5K; }
			if( iAmount < i6Mini )	
			{
				printf("isValidBitNetLotteryTx 1 Amount [%I64u] less than publish lottery's mini value [%I64u] :(\n", iAmount, i6Mini);
				return rzt;			
			}
			//nBestHeight  iBitNetBlockMargin3
			if( iTxHei > 0 )	// lottery tx bind on a block
			{
				if( (iTxHei < iStartBlock) || (iTxHei > (iEndBlock - iBitNetBlockMargin3)) )
				{ 
					printf("isValidBitNetLotteryTx 1, Hei (%u) not under rules, invalid :(\n", iTxHei);
					return rzt;
				}
			}
			else if( iFromType > 1 )	// iTxHei == 0, not exists, invalid
			{
				printf("isValidBitNetLotteryTx 1, From Type %u, Hei (%u) not under rules, invalid :(\n", iFromType, iTxHei);
				return rzt;
			}
			//if( iFromType > 1 ){ bCheckBlock = false; }	// from check bet tx
			if( bCheckBlock )	// bet tx dont check block
			{
				if( (iEndBlock > nBestHeight) && ((iEndBlock - nBestHeight) >= (BitNetBeginAndEndBlockMargin_Mini_30 - 10) ) ) // Target block must be a future block
				{ bBlockOk = true; }
			}else bBlockOk = true;
			if( fDebug ){ printf("isValidBitNetLotteryTx 1, TxHei = [%u], iStartBlock = [%I64u], iEndBlock = [%I64u], nBestHeight = [%u], bCheckBlock = [%u], bBlockOk = [%u]\n", iTxHei, iStartBlock, iEndBlock, nBestHeight, bCheckBlock, bBlockOk); }
			if( !bBlockOk )
			{
				printf("isValidBitNetLotteryTx 1, Current Hei (%u) not under rules, invalid :(\n", nBestHeight);
				return rzt;
			}
			
			if( (iEndBlock > iStartBlock) && ((iEndBlock - iStartBlock) >= BitNetBeginAndEndBlockMargin_Mini_30) )	// Target block number must big than start block
			{
				if( isValidPrivKeysAddress(sLotteryPrivKey, sLotteryAddr) > 0 )
				{
					if( GetCoinAddrInTxOutIndex(tx, sLotteryAddr, iAmount) >= 0 )	// Check Lottery Amount, =-1 is invalid
					{ 
						rzt++; 
						if( fDebug ){ printf("isValidBitNetLotteryTx 1, is Ok\n"); }
					}
					else{ printf("isValidBitNetLotteryTx 1, [%I64u] coins not send to [%s] :(\n", iAmount, sLotteryAddr.c_str()); }
				}
				else{ printf("isValidBitNetLotteryTx 1, Lottery PrivKey [%s]'s PubKey not  equ [%s] :(\n", sLotteryPrivKey.c_str(), sLotteryAddr.c_str()); }
			}
			else{ printf("isValidBitNetLotteryTx 1, Lottery Block (%I64u) : (%I64u) not under rules, invalid :(\n", iStartBlock, iEndBlock); }
		}
		
		else if( iCardType == 2 )	// Bet
		{
			//unsigned int GetTransactionBlockHeight(const string& TxID)
			if( sLotteryGenesisTxid.length() > 56 )	// tx id (20151c47f29dd01a828cd6197ce6563d4c184ecff3e34a0599fa2af8d6c65ef5) length = 64
			{
				iLotteryGenTxHei = GetTransactionBlockHeight(sLotteryGenesisTxid);	// get lottery create block number, iBitNetBlockMargin3
				if( iLotteryGenTxHei < BitNetLotteryStartTestBlock_286000 )
				{
					printf("isValidBitNetLotteryTx 2, Genesis Tx height (%u) is invalid :(\n", iLotteryGenTxHei); 
					return rzt;
				}
				//bool bCheckGenTxBlock = iFromType > 2;
				if( isValidBitNetLotteryTx(sLotteryGenesisTxid, 1, 2, iLotteryGenTxHei, false) > 0 )
				{
					i_gen = GetTxMsgParamS(sLotteryGenesisTxid, sLotId_gen, iCardType_gen, iGuessType_gen, iAmount_gen, iMiniBet_gen, iStartBlock_gen, iEndBlock_gen, iKeyLen_gen,
										sGuessTxt_gen, sLotteryAddr_gen, sLotteryPrivKey_gen, sMakerAddr_gen, sLotteryGenesisTxid_gen, sSignMsg_gen);
					if( i_gen < 15 )
					{
						printf("isValidBitNetLotteryTx 2, gen tx params number [%u] < 15 :(\n", i_gen);
						return rzt;
					}
					if( iCardType_gen != 1 )
					{
						printf("isValidBitNetLotteryTx 2, gen type [%u] != 1 :(\n", iCardType_gen);
						return rzt;
					}
					
					if( iTxHei > 0 )	// lottery tx bind on a block
					{
						if( (iTxHei < iStartBlock_gen) || (iTxHei > (iEndBlock_gen - iBitNetBlockMargin3)) )
						{
							printf("isValidBitNetLotteryTx 2, Hei (%u) not under rules, invalid :(\n", iTxHei);
							return rzt;
						}
					}
					else if( iFromType > 2 )	// iTxHei == 0, not exists, invalid
					{
						printf("isValidBitNetLotteryTx 2, From Type %u, Hei (%u) not under rules, invalid :(\n", iFromType, iTxHei);
						return rzt;
					}
			
					//if( iFromType > 2 ){ bCheckBlock = true; }	// from check Cash tx
					if( bCheckBlock )	// cash tx dont check block
					{
						if( (nBestHeight > iStartBlock_gen) && (nBestHeight <= (iEndBlock_gen - iBitNetBlockMargin3)) ){ bBlockOk = true; }
					}else bBlockOk = true;
					if( fDebug ){ printf("isValidBitNetLotteryTx 2, TxHei = [%u], nBestHeight = [%u], Gen Hei = [%u], iStartBlock_gen = [%I64u], iEndBlock_gen = [%I64u], bCheckBlock = [%u], bBlockOk = [%u]\n", iTxHei, nBestHeight, iLotteryGenTxHei, iStartBlock_gen, iEndBlock_gen, bCheckBlock, bBlockOk); }					
					if( !bBlockOk )
					{
						printf("isValidBitNetLotteryTx 2, bet invalid, not under rules :(\n");
						return rzt;
					}
					
					if( iAmount < iMiniBet_gen )
					{
						printf("isValidBitNetLotteryTx 2, bet Amount [%I64u] less than gen tx's MiniBet [%I64u] :(\n", iAmount, iMiniBet_gen);
						return rzt;
					}
					if( GetCoinAddrInTxOutIndex(tx, sLotteryAddr_gen, iAmount) >= 0 )	// Check bet is send to lottery gen tx's Address
					{
						rzt++;
						if( fDebug ){ printf("isValidBitNetLotteryTx 2, is Ok\n"); }
					}
					else{ printf("isValidBitNetLotteryTx 2, not found bet [%I64u] send to gen address [%s] :(\n", iAmount, sLotteryAddr_gen.c_str()); }				
				}
				else{ printf("isValidBitNetLotteryTx 2, Lottery Genesis Txid [%s] invalid :(\n", sLotteryGenesisTxid.c_str()); }
			}
			else{ printf("isValidBitNetLotteryTx 2, LotteryGenesisTxid [%s] too short, [%u]  byte :(\n", sLotteryGenesisTxid.c_str(), sLotteryGenesisTxid.length()); }
		}
		
		else if( iCardType == 3 )	// Cash
		{
			/* string sLotteryBetTxid = sLotteryGenesisTxid;
			if( sLotteryBetTxid.length() > 56 )	// tx id (20151c47f29dd01a828cd6197ce6563d4c184ecff3e34a0599fa2af8d6c65ef5) length = 64
			{
				int iLotteryBetTxHei = GetTransactionBlockHeight(sLotteryBetTxid);	// get lottery create block number, iBitNetBlockMargin3
				if( iLotteryBetTxHei < BitNetLotteryStartTestBlock_286000 )
				{
					printf("isValidBitNetLotteryTx 3, bet Tx height (%u) is invalid :(\n", iLotteryBetTxHei); 
					return rzt;
				}
				//bool bCheckGenTxBlock = iFromType > 2;
				if( isValidBitNetLotteryTx(sLotteryBetTxid, 2, 3, iLotteryBetTxHei, false) > 0 )
				{
				
					string sLotId_bet, sGuessTxt_bet, sLotteryAddr_bet, sLotteryPrivKey_bet, sMakerAddr_bet, sLotteryGenesisTxid_bet, sSignMsg_bet;
					int iCardType_bet, iGuessType_bet, iKeyLen_bet;
					int64_t iAmount_bet, iMiniBet_bet, iStartBlock_bet, iEndBlock_bet;
					int i_bet;
		
					i_bet = GetTxMsgParamS(sLotteryBetTxid, sLotId_bet, iCardType_bet, iGuessType_bet, iAmount_bet, iMiniBet_bet, iStartBlock_bet, iEndBlock_bet, iKeyLen_bet,
										sGuessTxt_bet, sLotteryAddr_bet, sLotteryPrivKey_bet, sMakerAddr_bet, sLotteryGenesisTxid_gen, sSignMsg_bet);
					if( i_bet < 15 )
					{
						printf("isValidBitNetLotteryTx 3, gen_params [%u] < 15 :(\n", i_bet);
						return rzt;
					}
					if( iCardType_gen != 1 )
					{
						printf("isValidBitNetLotteryTx 2, gen type [%u] != 1 :(\n", iCardType_gen);
						return rzt;
					}
					
					if( iTxHei > 0 )	// lottery tx bind on a block
					{
						if( (iTxHei < iStartBlock_gen) || (iTxHei > (iEndBlock_gen - iBitNetBlockMargin3)) )
						{
							printf("isValidBitNetLotteryTx 2, Hei (%u) not under rules, invalid :(\n", iTxHei);
							return rzt;
						}
					}
			
					//if( iFromType > 2 ){ bCheckBlock = true; }	// from check Cash tx
					if( bCheckBlock )	// cash tx dont check block
					{
						if( (nBestHeight > iStartBlock_gen) && (nBestHeight <= (iEndBlock_gen - iBitNetBlockMargin3)) ){ bBlockOk = true; }
					}else bBlockOk = true;
					if( fDebug ){ printf("isValidBitNetLotteryTx 2, TxHei = [%u], nBestHeight = [%u], Gen Hei = [%u], iStartBlock_gen = [%I64u], iEndBlock_gen = [%I64u], bCheckBlock = [%u], bBlockOk = [%u]\n", iTxHei, nBestHeight, iLotteryGenTxHei, iStartBlock_gen, iEndBlock_gen, bCheckBlock, bBlockOk); }					
					if( !bBlockOk )
					{
						printf("isValidBitNetLotteryTx 2, bet invalid, not under rules :(\n");
						return rzt;
					}
					
					if( iAmount < iMiniBet_gen )
					{
						printf("isValidBitNetLotteryTx 2, bet Amount [%I64u] less than gen tx's MiniBet [%I64u] :(\n", iAmount, iMiniBet_gen);
						return rzt;
					}
					if( GetCoinAddrInTxOutIndex(tx, sLotteryAddr_gen, iAmount) >= 0 )	// Check bet is send to lottery gen tx's Address
					{
						rzt++;
						if( fDebug ){ printf("isValidBitNetLotteryTx 2, is Ok\n"); }
					}
					else{ printf("isValidBitNetLotteryTx 2, not found bet [%I64u] send to gen address [%s] :(\n", iAmount, sLotteryAddr_gen.c_str()); }				
				}
				else{ printf("isValidBitNetLotteryTx 3, Bet Txid [%s] invalid :(\n", sLotteryBetTxid.c_str()); }
			}
			else{ printf("isValidBitNetLotteryTx 3, Lottery Bet Txid [%s] too short, [%u]  byte :(\n", sLotteryBetTxid.c_str(), sLotteryBetTxid.length()); }
			*/
		}
		else{ printf("isValidBitNetLotteryTx invalid Type [%u] :(\n", iCardType); }
	}
	else{ printf("isValidBitNetLotteryTx params count [%u] < 15 :(\n", i); }
	return rzt;
}

int64_t  getBetAmountFromTxOut(const CTransaction& tx, const string sLotteryGenAddr, std::vector<std::pair<string, string> >* entry, CCoinControl* coinControl = NULL)
{
	int64_t rzt = 0;
	if( !validateAddress(sLotteryGenAddr) ){ return rzt; }
	string sTxHash = tx.GetHash().ToString();
	//if( IsFinalTx(tx, nBestHeight + 1) )
	{
		string sMsg = tx.vpndata;
		//BOOST_FOREACH(const CTxOut& txout, tx.vout) 	
		for (unsigned int i = 0; i < tx.vout.size(); i++)
		{
			const CTxOut& txout = tx.vout[i];
			if( txout.nValue > 0 )
			{	
				txnouttype type;
				vector<CTxDestination> addresses;
				int nRequired;
				if( ExtractDestinations(txout.scriptPubKey, type, addresses, nRequired) )
				{
					BOOST_FOREACH(const CTxDestination& addr, addresses)
					{
						string sAa = CBitcoinAddress(addr).ToString();
						if( sAa == sLotteryGenAddr )	// is sent to Lottery genesis address
						{ 
							rzt = rzt + txout.nValue;
							if( entry != NULL )
							{
								string sFrom = "", sBetTxt = "";
								if( sMsg.length() > 30 )
								{
									sBetTxt = GetTxMsgParamIndex(tx, 10);	// 10 = Bet Txt
									sFrom = GetTxMsgParamIndex(tx, 13);	// 13 = Bettor Address
								}
								//printf("sBetTxt [%s] : [%s]\n", sBetTxt.c_str(), sFrom.c_str());
								string sBetAndTxt = strprintf("%dVPN, bet txt '%s'", (int)(txout.nValue / COIN), sBetTxt.c_str());
								//std::vector<std::pair<string, string> > *item = (std::vector<std::pair<string, string> > *)entry;
								entry->push_back(make_pair(sFrom, sBetAndTxt));	//item->push_back(Pair(sFrom, sBetAndTxt));
								//entry->push_back(Pair(sFrom, iii));
							}
							if( coinControl != NULL )
							{
								COutPoint outpt(uint256(sTxHash), i);
								coinControl->Select(outpt);
								if( fDebug ){ outpt.print(); }
							}
							if( fDebug ){ printf( "GetBetAmountFromTxOut: index = [%u], bet [%I64u] sent to [%s], rzt = [%I64u], Tx Hash [%s] \n", i, (txout.nValue / COIN), sAa.c_str(), (rzt / COIN), sTxHash.c_str() ); }
						}
					}
				}
			}
		}
	}
	return rzt;
}

int64_t getBetAmountFromBlock(int nHeight, const string sLotteryGenAddr, std::vector<std::pair<string, string> >* entry, CCoinControl* coinControl = NULL)
{
    int64_t rzt = 0;
	if (nHeight < 0 || nHeight > nBestHeight){ return rzt; }
	if( !validateAddress(sLotteryGenAddr) ){ return rzt; }

    CBlockIndex* pblockindex = FindBlockByHeight(nHeight);
	if( pblockindex )
	{
		CBlock block;
		block.ReadFromDisk(pblockindex);
		//int nHeight = pblockindex->nHeight;
			
		BOOST_FOREACH(const CTransaction& tx, block.vtx)
		{
			if (!IsFinalTx(tx, nHeight, block.GetBlockTime()))
				return rzt;
			
			//if( (!tx.IsCoinBase()) && (!tx.IsCoinStake()) )
			{
				int64_t r6 = getBetAmountFromTxOut(tx, sLotteryGenAddr, entry, coinControl);
				if( r6 > 0 )
				{
					rzt = rzt + r6;
					if( fDebug ){ printf( "getBetAmountFromBlock: [%u] bet [%I64u] to [%s], rzt = [%I64u] \n", nHeight, (r6 / COIN), sLotteryGenAddr.c_str(), (rzt / COIN) ); }
				}
			}	
		}		
	}
	return rzt;
}

int64_t getBetAmountFromBlockRange(int iBlockBegin, int iBlockEnd, const string sLotteryGenAddr, std::vector<std::pair<string, string> >* entry, CCoinControl* coinControl = NULL)
{
	int64_t rzt = 0;
	if( !validateAddress(sLotteryGenAddr) ){ return rzt; }
	if( fDebug ){ printf("getBetAmountFromBlockRange: [%u] ~ [%u], Genesis Addr [%s] \n", iBlockBegin, iBlockEnd, sLotteryGenAddr.c_str()); }
	int j = iBlockEnd;
	if( iBlockEnd > nBestHeight )
	{
		j = nBestHeight;
		printf("getBetAmountFromBlockRange: Block end [%u] : [%u] not exists \n", iBlockEnd, nBestHeight);
		//return rzt; 
	}
	j++;

	for(int i = iBlockBegin; i < j; i++ )
	{
		int64_t r6 =	getBetAmountFromBlock(i, sLotteryGenAddr, entry, coinControl);
		if( r6 > 0 )
		{
			rzt = rzt + r6;
			if( fDebug ){ printf( "getBetAmountFromBlockRange: [%u] bet [%I64u] to [%s], rzt = [%I64u] \n", i, (r6 / COIN), sLotteryGenAddr.c_str(), (rzt / COIN) ); }
		}
	}
	return rzt;	
}

//getbetamountfromblockrange 286893 296290 VtMFv3vAdnBRod4SjmnPPf88boeBmcbgo3
Value getbetamountfromblockrange(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "getbetamountfromblockrange <begin block> <end block> <coin address>\n"
            "Return all from <begin block> ~ <end block> sent to <coin address>'s coin amount.");

    int nBegin = params[0].get_int();
    int nEnd= params[1].get_int();
    if ( (nBegin < 0) ||  (nEnd <= nBegin) )
        throw runtime_error("Block number out of range.");
		
    string sAddr = params[2].get_str();
    //Object entry;
	std::vector<std::pair<string, string> > entry;
    //entry.push_back(Pair("Betting List", ""));
	int64_t r6 = getBetAmountFromBlockRange(nBegin, nEnd, sAddr, &entry);
	
    Object ret;
	ret.push_back( Pair("address", sAddr) );
    ret.push_back( Pair("amount", ValueFromAmount(r6)) );
//void TxToJSON(const CTransaction& tx, const uint256 hashBlock, Object& entry)	
    //ret.push_back(entry);
	ret.push_back(Pair("Betting List", ""));  //ret.push_back(Pair("Betting Count", entry.size()));
	BOOST_FOREACH(const PAIRTYPE(string, string)& item, entry)
	{
		//string s = item.first + "\t" + item.second; //strprintf("%d", item.second);
		ret.push_back(Pair(item.first, item.second));
	}
	//ret.push_back(Pair("Betting List", entry));
    return ret;
}

/*
GetBetBiggerWinnerFromTxOut
Assume tx, iTargetGuessLen, iTargetGuessType, sCorrectAnswer, sLotteryGenAddr, v_TargetValue all are right,
Caller need verify these params.
*/
int  GetBetBiggerWinnerFromTxOut(const CTransaction& tx, int iTargetGuessLen, int iTargetGuessType, const string sCorrectAnswer, const string sLotteryGenAddr, 
												   int64_t v_TargetValue, string& sRztBiggerAddr, int64_t& i6RztBiggerValue, int iCmpType)
{
	int rzt = 0;
	//sRztBiggerAddr = "";
	//i6RztBiggerValue = 0;
	//if( IsFinalTx(tx, nBestHeight + 1) )
	{
		string sLotId, sGuessTxt, sLotteryAddr, sLotteryPrivKey, sMakerAddr, sLotteryGenesisTxid, sSignMsg;
		int iLotteryType, iGuessType, iGuessLen;
		int64_t iAmount, iMiniBet, iStartBlock, iEndBlock;
	
		int i = GetTxMsgParam(tx, sLotId, iLotteryType, iGuessType, iAmount, iMiniBet, iStartBlock, iEndBlock, iGuessLen, sGuessTxt, sLotteryAddr, sLotteryPrivKey, sMakerAddr, sLotteryGenesisTxid, sSignMsg);
		if( (i < 15) || (iGuessLen != iTargetGuessLen) || (iGuessType != iTargetGuessType) || (iLotteryType < 1) || (iLotteryType > 2 ) || (iAmount < v_TargetValue) )	// 1~2 is correct
		{
			return rzt;
		}
		//validateAddress
		if(  (!validateAddress(sLotteryAddr)) || (!validateAddress(sLotteryGenAddr)) || (sLotteryGenAddr != sLotteryAddr) ){ return rzt; }
		if( (sGuessTxt != sCorrectAnswer) || (!validateAddress(sMakerAddr)) ){ return rzt; }
	
		int64_t i6R = v_TargetValue;
		int vCmpType = iCmpType;
		//BOOST_FOREACH(const CTxOut& txout, tx.vout) 	
		for (unsigned int i = 0; i < tx.vout.size(); i++)
		{
			const CTxOut& txout = tx.vout[i];
			bool bOk = false;
			if( vCmpType == 0 ){ bOk = (txout.nValue > i6R); }
			else if( vCmpType == 1 ){ bOk = (txout.nValue >= i6R); }
if( fDebug ){ printf("GetBetBiggerWinnerFromTxOut: \n\t CmpType %u, bOk = %u, txout nValue [%I64u : %I64u] \n", vCmpType, bOk, (txout.nValue / COIN), (i6R / COIN)); }
			if( bOk )	//if( txout.nValue > i6R )
			{	
				txnouttype type;
				vector<CTxDestination> addresses;
				int nRequired;
				if( ExtractDestinations(txout.scriptPubKey, type, addresses, nRequired) )
				{
					BOOST_FOREACH(const CTxDestination& addr, addresses)
					{
						string sAa = CBitcoinAddress(addr).ToString();
						if( sAa == sLotteryGenAddr )	// is sent to Lottery genesis address
						{ 
							i6R = txout.nValue;
							rzt++;   vCmpType = 0;	// set cmp type to "big than"
							if( fDebug ){ printf("GetBetBiggerWinnerFromTxOut: BiggerWinner is [%s], bet [%I64u], index [%d] \n", sMakerAddr.c_str(), (i6R / COIN), i); }
						}
					}
				}else{ if( fDebug ){ printf("GetBetBiggerWinnerFromTxOut: (%u) ExtractDestinations failed \n", i); } }
			}
		}
		if( rzt > 0 )
		{
			sRztBiggerAddr = sMakerAddr;
			i6RztBiggerValue = i6R;
			if( fDebug ){ printf("GetBetBiggerWinnerFromTxOut: Return BiggerWinner is [%s], bet [%I64u], rzt = [%d] \n", sRztBiggerAddr.c_str(), (i6RztBiggerValue / COIN), rzt); }
		}
	}
	return rzt;
}

/*
getBetBiggerWinnerFromBlock
Assume tx, iTargetGuessLen, iTargetGuessType, sCorrectAnswer, sLotteryGenAddr, v_TargetValue all are right,
Caller need verify these params.
*/
int getBetBiggerWinnerFromBlock(int nHeight, int iTargetGuessLen, int iTargetGuessType, const string sCorrectAnswer, const string sLotteryGenAddr, 
																  int64_t v_TargetValue, string& sRztBiggerAddr, int64_t& i6RztBiggerValue, int iCmpType)
{
    int rzt = 0;
	if (nHeight < 0 || nHeight > nBestHeight){ return rzt; }
	if( sLotteryGenAddr.length() < 34 ){ return rzt; }
	if( fDebug ){ printf("getBetBiggerWinnerFromBlock: nHeight [%u],  iCmpType [%u], sLotteryGenAddr = [%s] \n", nHeight, iCmpType, sLotteryGenAddr.c_str()); }
    CBlockIndex* pblockindex = FindBlockByHeight(nHeight);
	if( pblockindex )
	{
		CBlock block;
		block.ReadFromDisk(pblockindex);
		//int nHeight = pblockindex->nHeight;
		int64_t i6BigBet = 0, i6TargetValue = v_TargetValue;
		string sBigWinner = "";
				
		// Check that all transactions are finalized
		BOOST_FOREACH(const CTransaction& tx, block.vtx)
		{
			if (!IsFinalTx(tx, nHeight, block.GetBlockTime()))
			{
				if( fDebug ){ printf("getBetBiggerWinnerFromBlock: IsFinalTx return false :(\n"); }
				continue;		//return rzt;
			}
			//if( (!tx.IsCoinBase()) && (!tx.IsCoinStake()) )
			//{
				if( GetBetBiggerWinnerFromTxOut(tx, iTargetGuessLen, iTargetGuessType, sCorrectAnswer, sLotteryGenAddr, i6TargetValue, sBigWinner, i6BigBet, iCmpType) > 0 )
				{
					rzt++;
					i6TargetValue = i6BigBet;
					i6RztBiggerValue = i6BigBet;
					sRztBiggerAddr = sBigWinner;
					if( fDebug ){ printf("getBetBiggerWinnerFromBlock: BiggerWinner is [%s], bet [%I64u], rzt = [%d] \n", sRztBiggerAddr.c_str(), (i6RztBiggerValue / COIN), rzt); }
				}//else if( fDebug ){ printf("getBetBiggerWinnerFromBlock: GetBetBiggerWinnerFromTxOut return 0 :(\n"); }
			//}	
		}		
	}else if( fDebug ){ printf("getBetBiggerWinnerFromBlock: pblockindex = NULL :(\n"); }
	return rzt;
}

/*
getBetBiggerWinnerFromBlockRange
Assume tx, iTargetGuessLen, iTargetGuessType, sCorrectAnswer, sLotteryGenAddr, v_TargetValue all are right,
Caller need verify these params.
*/
int getBetBiggerWinnerFromBlockRange(int iBlockBegin, int iBlockEnd, int iTargetGuessLen, int iTargetGuessType, const string sCorrectAnswer, const string sLotteryGenAddr, 
																  int64_t v_TargetValue, string& sRztBiggerAddr, int64_t& i6RztBiggerValue)
{
	int rzt = 0;
	if( fDebug ){
		printf("getBetBiggerWinnerFromBlockRange: [%u] ~ [%u], Guess Len [%u], Type [%u], Answer [%s], Genesis Addr [%s], Target Amount [%I64u]VPN \n", 
				  iBlockBegin, iBlockEnd, iTargetGuessLen, iTargetGuessType, sCorrectAnswer.c_str(), sLotteryGenAddr.c_str(), (v_TargetValue / COIN)); 
	}
	if( iBlockEnd > nBestHeight )
	{
		if( fDebug ){ printf("getBetBiggerWinnerFromBlockRange: Target Block [%u] : [%u] not exist \n", iBlockEnd, nBestHeight); }
		return rzt; 
	}

	int64_t i6BigBet = 0, i6TargetValue = v_TargetValue;
	string sBigWinner = "";
	int iCmpType = 1;	// first time, cmp type = "equ or big than"
	for(int i = iBlockBegin; i <= iBlockEnd ; i++ )
	{
		if( getBetBiggerWinnerFromBlock(i, iTargetGuessLen, iTargetGuessType, sCorrectAnswer, sLotteryGenAddr, i6TargetValue, sBigWinner, i6BigBet, iCmpType) > 0 )
		{
			i6TargetValue = i6BigBet;
			i6RztBiggerValue = i6BigBet;
			sRztBiggerAddr = sBigWinner;
			rzt++;   iCmpType = 0;	// set cmp type = "big than"
			if( fDebug ){ printf("getBetBiggerWinnerFromBlockRange: BiggerWinner is [%s], Bet [%I64u], rzt = [%d] \n", sRztBiggerAddr.c_str(), (i6RztBiggerValue / COIN), rzt); }
		}
	}
	return rzt;	
}

//string getTxin_prevout_n_s_sendto_address(const CTransaction& tx, unsigned int n)
bool is_Txin_prevout_n_s_sendto_address(const uint256& prevoutHash, unsigned int n, const string& sTargetAddress)
{
	bool rzt = false;
	bool bValid = validateAddress(sTargetAddress);
	string txID = prevoutHash.GetHex();
	if( fDebug ){ printf("is_Txin_prevout_n_s_sendto_address: Tag Address [%s] Valid = [%u], n = [%u], tx id = [%s] \n", sTargetAddress.c_str(), bValid, n, txID.c_str()); }
	if( !bValid ){ return rzt; }
	
	CTransaction tx;
	if( GetValidTransaction(txID, tx) > 0 )
	{	
		if( fDebug ){ printf("is_Txin_prevout_n_s_sendto_address: tx.vout.size() = [%u] : [%u] \n", tx.vout.size(), n); }
		if( tx.vout.size() > n )
		{
			const CTxOut& txout = tx.vout[n];
			txnouttype type;
			vector<CTxDestination> addresses;
			int nRequired;

			if( ExtractDestinations(txout.scriptPubKey, type, addresses, nRequired) )
			{
				BOOST_FOREACH(const CTxDestination& addr, addresses)
				{
					//rzt = strprintf("%s|%s", rzt.c_str(), CBitcoinAddress(addr).ToString().c_str());
					string sAa = CBitcoinAddress(addr).ToString();
					if( fDebug ){ printf("is_Txin_prevout_n_s_sendto_address: txout[%u].scriptPubKey's address = [%s] \n", n, sAa.c_str()); }
					if( sAa == sTargetAddress )
					{
						if( fDebug ){ printf("is_Txin_prevout_n_s_sendto_address: Yes :) \n"); }
						return true;
					}
				}
			}			
		}
	}
	return rzt;
} //is_Txin_prevout_n_s_sendto_address

//bool get_Txin_prevout_n_s_TargetAddressAndAmount(const uint256& prevoutHash, unsigned int n, string& sTargetAddress, int64_t& iAmnt)
bool get_Txin_prevout_n_s_TargetAddressAndAmount(const CTransaction& tx, unsigned int n, string& sTargetAddress, int64_t& iAmnt)
{
	bool rzt = false;
	sTargetAddress = "";  iAmnt = 0;
	string txID = tx.GetHash().ToString();  //prevoutHash.GetHex();
	if( fDebug ){ printf("get_Txin_prevout_n_s_TargetAddressAndAmount: n = [%d], tx id = [%s] \n", n, txID.c_str()); }
	
	//CTransaction tx;
	//if( GetValidTransaction(txID, tx) > 0 )
	{	
		if( fDebug ){ printf("get_Txin_prevout_n_s_TargetAddressAndAmount: tx.vout.size() = [%u] : [%u] \n", tx.vout.size(), n); }
		if( tx.vout.size() > n )
		{
			const CTxOut& txout = tx.vout[n];
			txnouttype type;
			vector<CTxDestination> addresses;
			int nRequired;

			if( ExtractDestinations(txout.scriptPubKey, type, addresses, nRequired) )
			{
				BOOST_FOREACH(const CTxDestination& addr, addresses)
				{
					//rzt = strprintf("%s|%s", rzt.c_str(), CBitcoinAddress(addr).ToString().c_str());
					string sAa = CBitcoinAddress(addr).ToString();
					if( fDebug ){ printf("get_Txin_prevout_n_s_TargetAddressAndAmount: txout[%u].scriptPubKey's address = [%s] \n", n, sAa.c_str()); }
					if( sAa.length() > 30 )
					{
						sTargetAddress = sAa.c_str();   iAmnt = txout.nValue;
						if( fDebug ){ printf("get_Txin_prevout_n_s_TargetAddressAndAmount: [%s] [%I64u] :) \n", sTargetAddress.c_str(), iAmnt); }
						return true;
					}
				}
			}			
		}
	}
	return rzt;
}  //get_Txin_prevout_n_s_TargetAddressAndAmount

#ifdef USE_BITNET 
extern DWORD bServiceMode;
extern int SyncGenLotteryToGui(unsigned int nTime, unsigned int iHi, int64_t aMount, string sMaker, string sId, string sTxMsg);
extern int IsMonitorTx(unsigned int nTime, unsigned int iHi, string Txid, const CTransaction& tx, unsigned int n);
#endif

bool getTxinAddressAndAmount(const CTxIn& txin, string& sPreTargetAddr, int64_t& iAmnt)
{
	bool rzt = false;
	if( txin.prevout.IsNull() ){ return rzt; }

    uint256 hashBlock = 0;
    CTransaction txPrev;
    //if( fDebug ){ printf( "getTxinAddressAndAmount: txin.prevout.n = [%u], \n", txin.prevout.n ); }
	if( GetTransaction(txin.prevout.hash, txPrev, hashBlock) )	// get the vin's previous transaction
	{
		sPreTargetAddr = "";
		iAmnt = 0;
		rzt = get_Txin_prevout_n_s_TargetAddressAndAmount(txPrev, txin.prevout.n, sPreTargetAddr, iAmnt);
	}
	return rzt;
}

/*const std::string str_BitNet_Freeze = "BitNet Freeze";
int isValidFreezeTx(const CTransaction& tx, unsigned int iTxHei, int* iRztFreezeTm = NULL, string* sRztPayToAddr = NULL, string* sRztTargetAddr = NULL, int* iFee = 0)
{
	int rzt = -1;
	string sTxMsg = tx.vpndata.c_str();  // BitNet Freeze|60|Vxxxxx..........|Target Address
    if( sTxMsg.length() < 13 ){ return rzt; }

	if( sTxMsg.find(str_BitNet_Freeze) != 0 ){ return rzt; }   //std::string::npos	
	char *delim = "|";
	int i = 0;
	string sHead = "", sTargetAddr = "", sPayToAddr = "";
	int iFreezeTm = 0, iRelayFee = 0;
				
	char * pVpn = (char *)sTxMsg.c_str();
	char* pch = strtok(pVpn, delim);
	while (pch != NULL)
	{
		i++;
		if( i == 1 ){
			sHead = pch;
			if( sHead != str_BitNet_Freeze ){ return rzt; }
		}
		else if( i == 2 ){ iFreezeTm = atoi(pch); }
		else if( i == 3 ){ sPayToAddr = pch; }
		else if( i == 4 ){ sTargetAddr = pch; }
		else if( i == 5 ){ iRelayFee = atoi(pch);  break; }
		pch = strtok (NULL, delim);
	}

	if( fDebug ){ printf("isValidFreezeTx:: [%s] [%d], PayTo [%s], Target [%s], Fee [%d] \n", sHead.c_str(), iFreezeTm, sPayToAddr.c_str(), sTargetAddr.c_str(), iRelayFee); }
	if( iFreezeTm <= 0 ){ return 0; }

	if( validateAddress(sPayToAddr) )
	{
		if( (sTargetAddr.length() > 0) && (!validateAddress(sTargetAddr)) ){ return 0; }
		if( iRztFreezeTm != NULL ){ *iRztFreezeTm = iFreezeTm; }
		if( sRztPayToAddr != NULL ){ *sRztPayToAddr = sPayToAddr.c_str(); }
		if( sRztTargetAddr != NULL ){ *sRztTargetAddr = sTargetAddr.c_str(); }
		if( iFee != NULL ){ *iFee = iRelayFee; }
		int  v = GetCoinAddrInTxOutIndex(tx, sPayToAddr, (10 * COIN), 3);
		if( fDebug ){ printf("isValidFreezeTx:: v = [%d] \n", v); }
		if( v == -1 ){ rzt = 0; }
		else{ rzt = 1; }
	}else rzt = 0;
    if( fDebug ){ printf("isValidFreezeTx:: rzt = [%d] \n", rzt); }
	return rzt;
}

bool isFreezeTx(const CTransaction& curTx, int curTxHei, const CTransaction& txPrev, unsigned int iPreTxHei,  unsigned int txin_prevout_n)
{
	bool rzt = false;

	string sPayToAddr = "", sTargetAddr = "";
	int iFreezeTm = 0, iRelayFee = 0;
	int i = isValidFreezeTx(txPrev, iPreTxHei, &iFreezeTm, &sPayToAddr, &sTargetAddr, &iRelayFee);
	if( i < 1 ){ return rzt; }
	if( fDebug ){ printf("isFreezeTx:: PreTxHei = [%d], n = [%d], FreezeTm = [%d], Payto [%s], \n\t Target [%s], Relay Fee = [%d]\n", iPreTxHei, txin_prevout_n, iFreezeTm, sPayToAddr.c_str(), sTargetAddr.c_str(), iRelayFee); }
	if( iFreezeTm == 0 ){ return rzt; }

	if( validateAddress(sPayToAddr) )
	{
		string sPreTargetAddr = "";
		int64_t iAmnt = 0;
		int Thawing_time = iPreTxHei + iFreezeTm;
		if( get_Txin_prevout_n_s_TargetAddressAndAmount(txPrev, txin_prevout_n, sPreTargetAddr, iAmnt) )
		{
			double db = (double)iAmnt / (double)COIN;
			if( fDebug ){ printf("isFreezeTx:: n = [%d] [%s] [%f], Thawing time [%d :: %d] \n", txin_prevout_n, sPreTargetAddr.c_str(), db, Thawing_time, curTxHei); }
			if( iAmnt < (10 * COIN) ){ return rzt; }
			else if( sPreTargetAddr == sPayToAddr )
			{
				if( curTxHei < Thawing_time ){
					rzt = true;
					if( fDebug ){ printf("isFreezeTx:: curTxHei [%d] <  Thawing_time [%d] \n", curTxHei, Thawing_time); }
				}
				else{
					if( (sTargetAddr.length() > 30) && (validateAddress(sTargetAddr)) )
					{
						int imt = iAmnt / COIN;
						if( (iRelayFee <= 0) || (iRelayFee > imt) ){ iRelayFee = 1; }
						int64_t v_nValue = iAmnt - (iRelayFee * COIN);
						int j = GetCoinAddrInTxOutIndex(curTx, sTargetAddr,  v_nValue, 3);
						if( fDebug ){ printf("isFreezeTx:: TxOutIndex = [%d] \n", j); }
						if( j == -1 ){ rzt = true; }
					}else if( fDebug ){ printf("isFreezeTx:: Target Address [%s] is empt or invalid \n", sTargetAddr.c_str()); }
				}
			}
		}
	}
	if( fDebug ){ printf("isFreezeTx:: rzt = [%d] \n", rzt); }
	if( NewTxFee_RewardCoinYear_Active_Height > nBestHeight ){ rzt = false; }
	return rzt;
}*/

bool isRejectTransaction(const CTransaction& tx, unsigned int iTxHei)
{
	bool rzt = false;
	bool bCasherIsWinner = false;
	if( nBestHeight <= BitNetLotteryStartTestBlock_286000 ){ return rzt; }
	//-- first check it is a valid lottery tx, 
	string sCashTxHash = tx.GetHash().ToString();
	if( fDebug ){ printf("\n\n\n******************** begin [%s]\n", sCashTxHash.c_str()); }
	int iCashTxHei = iTxHei;  //GetTransactionBlockHeight(sCashTxHash);
	if( iCashTxHei == 0 )
	{ 
		if( fDebug )printf("isRejectTransaction: Enash tx's hei = [%u], set to nBestHeight [%u] \n", iCashTxHei, nBestHeight); 
		iCashTxHei = nBestHeight;  
	}
	string sTxMsg = tx.vpndata;
	if( fDebug ){ printf("isRejectTransaction: Tx hei = [%u], nBestHeight [%u], \n\t Tx Msg = [%s] \n", iCashTxHei, nBestHeight, sTxMsg.c_str()); }
	
	string sLotId_cash = "", sGuessTxt = "", sLotteryAddr_bet = "", sLotteryPrivKey_bet = "", sMakerAddr_cash = "", sLotteryBetTxid = "", sSignMsg = "";
	int iLotteryType_cash = 0, iGuessType = 0, iKeyLen = 0;
	int64_t iAmount = 0, iMiniBet = 0, iStartBlock = 0, iEndBlock = 0;
	
	string sRztBiggerAddr = "", sCashTxLinkedGenesisTx = "";
	int64_t i6RztBiggerValue = 0;	
	
	bool bCashMsgSignOk = false;
	int i = 0, iWillBan = 0;

#ifdef USE_BITNET 	
	if( iTxHei > 0 )  // 2015.06.21 add, Monitor Tx and sync to gui
	{
		if( (bServiceMode == 0) && GetArg("-monitortx", 1) )
		{
			//if( !pwalletMain->IsMine(tx) )
			{ 
				IsMonitorTx(tx.nTime, iTxHei, sCashTxHash, tx, 0xFFFFFFFF); 
			}
		}
	}
#endif
	
	if( iCashTxHei < BitNetLotteryStartTestBlock_286000 ){ goto check_Complete; }
	if( sTxMsg.length() < 34){ goto check_Complete; }
	
	i = GetTxMsgParam(tx, sLotId_cash, iLotteryType_cash, iGuessType, iAmount, iMiniBet, iStartBlock, iEndBlock, iKeyLen, 
						sGuessTxt, sLotteryAddr_bet, sLotteryPrivKey_bet, sMakerAddr_cash, sLotteryBetTxid, sSignMsg);
	if( i > 14 ) 
	{
		string sLotteryAnswer = "";
		if(  iLotteryType_cash != 3 )		// if not a cash tx
		{
			if( iLotteryType_cash == 1 )	// is Genesis tx
			{
				if( fDebug ){ printf("isRejectTransaction: is a Genesis Lottery tx \n", sCashTxHash.c_str(), sSignMsg.c_str()); }
				if( isValidLotteryGenesisTx(tx, iCashTxHei, -1, -1, 0, "", "") == false )
				{
					iWillBan++;  printf("isRejectTransaction: Genesis tx [%s] not under rules, will ban :(\n", sCashTxHash.c_str());
					if( isBitNetLotteryRuleStart() )
					{
						if( fDebug ){ printf("[%s] end ********************\n\n\n", sCashTxHash.c_str()); }
						return true; 
					}
				}else if( iTxHei > 0 ){
#ifdef USE_BITNET 
					if( bServiceMode == 0 ){ SyncGenLotteryToGui(tx.nTime, iTxHei, iAmount, sMakerAddr_cash, sCashTxHash, sTxMsg); }
#endif
				}
			}
			else if( iLotteryType_cash == 2 )	// is Bet tx
			{
//bool isValidLotteryBetTx(const CTransaction& tx, int iTxHei, int iTargetGuessType, int iTargetGuessLen, int64_t i6TargetBlock, const string sTargetMaker, const string sTargetGenesisAddr)
				if( fDebug ){ printf("isRejectTransaction: is a Bet Lottery tx \n", sCashTxHash.c_str(), sSignMsg.c_str()); }
				if( isValidLotteryBetTx(tx, iCashTxHei, -1, -1, 0, "", "") == false )
				{
					iWillBan++;  printf("isRejectTransaction: Bet tx [%s] not under rules, will ban :(\n", sCashTxHash.c_str());
					if( isBitNetLotteryRuleStart() )
					{
						if( fDebug ){ printf("[%s] end ********************\n\n\n", sCashTxHash.c_str()); }
						return true; 
					}
				}
			}else{ printf("isRejectTransaction: [%s] not a Lottery tx, invalid type [%u] \n", sCashTxHash.c_str(), iLotteryType_cash); }
			goto check_Complete;				
		}
// is a Encash lottery tx
		if( fDebug ){ printf("isRejectTransaction: is a Encash Lottery tx \n", sCashTxHash.c_str(), sSignMsg.c_str()); }
		//if( validateAddress(sMakerAddr_cash) == false ){ goto check_Complete; }
		if( sSignMsg.length() < 60 ){
			printf("isRejectTransaction: Encash tx [%s]'s  msg sign [%s] invalid \n", sCashTxHash.c_str(), sSignMsg.c_str());
			goto check_Complete;		
		}
		if( verifyMessage(sMakerAddr_cash, sSignMsg, sLotteryBetTxid) == false )	// check cash sender is sMakerAddr_cash's owner
		{
			printf("isRejectTransaction: Encash tx [%s] sign invalid \n", sCashTxHash.c_str());
			goto check_Complete;
		}
		bCashMsgSignOk = true;
		if( fDebug ){ printf("isRejectTransaction: Encash Msg Sign Ok \n"); }
		
		string sLotId_bet, sGuessTxt_bet, sMakerAddr_bet, sLotteryLinkedTxid_gen, sSignMsg_bet;
		int iLotteryType_bet, iGuessType_bet, iKeyLen_bet;
		int64_t iAmount_bet, iMiniBet_bet, iStartBlock_bet, iEndBlock_bet;
				
		int iBetTxHei = GetTransactionBlockHeight(sLotteryBetTxid);
		if( iBetTxHei < BitNetLotteryStartTestBlock_286000 )
		{
			printf("isRejectTransaction: Bet tx [%s] not exists or invalid, hei =[%u] \n", sLotteryBetTxid.c_str(), iBetTxHei);
			goto check_Complete;
		}
// get linked bet tx info
		i = GetTxMsgParamS(sLotteryBetTxid, sLotId_bet, iLotteryType_bet, iGuessType_bet, iAmount_bet, iMiniBet_bet, iStartBlock_bet, iEndBlock_bet, iKeyLen_bet,
						sGuessTxt_bet, sLotteryAddr_bet, sLotteryPrivKey_bet, sMakerAddr_bet, sLotteryLinkedTxid_gen, sSignMsg);
		if( i < 15 )
		{
			printf("isRejectTransaction: Encash tx [%s] linked bet tx [%s] is invalid, params count < 15 \n", sCashTxHash.c_str(), sLotteryBetTxid.c_str()); 
			goto check_Complete;
		}
		if( sMakerAddr_cash != sMakerAddr_bet )		
		{
			printf("isRejectTransaction: Encash tx [%s] maker [%s] != bet tx [%s] maker [%s], invalid \n", sCashTxHash.c_str(), sMakerAddr_cash.c_str(), sLotteryBetTxid.c_str(), sMakerAddr_bet.c_str()); 
			goto check_Complete;
		}		
		if(  iLotteryType_bet != 2 )
		{
			if(  iLotteryType_bet != 1 )	// If no one guessed, Lottery maker can cash it.
			{
				printf("isRejectTransaction: [%s] not a bet and genesis tx, invalid type \n", sLotteryBetTxid.c_str());
				goto check_Complete;
			}
			if( fDebug ){ printf("isRejectTransaction: Encash tx linked genesis lottery \n"); }
// Is a Genesis lottery, Cash tx linked a Genesis tx, sMakerAddr_cash must be this lottery's creater
			if( iCashTxHei < (iEndBlock_bet + iBitNetBlockMargin3) )
			{
				printf("isRejectTransaction: Can't Encash, iCashTxHei [%u] < [%I64u], please wait :(\n", iCashTxHei, (iEndBlock_bet + iBitNetBlockMargin3));
				goto check_Complete;	
			}
			/* if( sMakerAddr_cash != sMakerAddr_bet ){
				printf("sMakerAddr_cash [%s] != sMakerAddr_bet [%s], not this lottery's creater :( ", sMakerAddr_cash.c_str(), sMakerAddr_bet.c_str());
				goto check_Complete; 
			} */
//bool isValidLotteryGenesisTxs(const string& txID, int iTxHei, int iTargetGuessType, int iTargetGuessLen, int64_t i6TargetBlock, const string sTargetMaker, const string sTargetGenesisAddr)
			if( isValidLotteryGenesisTxs(sLotteryBetTxid, iBetTxHei, -1, -1, 0, sMakerAddr_cash, "", true) == false )
			{
				printf("isRejectTransaction: [%s] is a genesis tx, but not under rules :(\n", sLotteryBetTxid.c_str());
				goto check_Complete;	
			}
			sCashTxLinkedGenesisTx = sLotteryBetTxid.c_str();
// sMakerAddr_cash is this lottery's creater
// scan all of (iStartBlock ~ iEndBlock) blocks, find Bet biggest winner
			sLotteryAnswer = getBlockNByteHashStrByType(iEndBlock_bet, iKeyLen_bet, iGuessType_bet);
			if( fDebug ){ printf("isRejectTransaction:  sLotteryAnswer = [%s], sGuessTxt_bet = [%s] \n", sLotteryAnswer.c_str(), sGuessTxt_bet.c_str()); }
//int getBetBiggerWinnerFromBlockRange(int iBlockBegin, int iBlockEnd, int iTargetGuessLen, int iTargetGuessType, const string sCorrectAnswer, const string sLotteryGenAddr, 
//																  int64_t v_TargetValue, string& sRztBiggerAddr, int64_t& i6RztBiggerValue)															  
			if( getBetBiggerWinnerFromBlockRange(iStartBlock_bet, (iEndBlock_bet - iBitNetBlockMargin3), iKeyLen_bet, iGuessType_bet, sLotteryAnswer, sLotteryAddr_bet, iMiniBet_bet, sRztBiggerAddr, i6RztBiggerValue) > 0 )
			{
				// someone guessed
				if( sRztBiggerAddr == sMakerAddr_cash )
				{
					bCasherIsWinner = true;
					if( fDebug ){ printf("isRejectTransaction: [%s] linked genesis lottery [%s]'s \n\t winner is creator [%s]\n", sCashTxHash.c_str(), sLotteryBetTxid.c_str(), sRztBiggerAddr.c_str()); }
				}else{ if( fDebug ){ printf("isRejectTransaction: [%s] linked genesis lottery [%s]'s \n\t winner is [%s], not creator [%s] \n", sCashTxHash.c_str(), sLotteryBetTxid.c_str(), sRztBiggerAddr.c_str(), sMakerAddr_cash.c_str()); } }
			}else{	// no one guessed, lottery creater is winner
				sRztBiggerAddr = sMakerAddr_cash;
				i6RztBiggerValue = iAmount_bet;
				bCasherIsWinner = true;
				if( fDebug ){ printf("isRejectTransaction: no one guessed, [%s] linked genesis lottery [%s]'s \n\t winner is creator [%s]\n", sCashTxHash.c_str(), sLotteryBetTxid.c_str(), sRztBiggerAddr.c_str()); }
			}
			goto check_Complete;	
		}
// is lottery bet tx
		if( fDebug ){ printf("isRejectTransaction: Encash tx linked Bet Lottery \n"); }
		if( (iGuessType_bet < 0) || (iGuessType_bet > 1) )	// 0 = guess n byte of block hash text,  1 = guess n byte of block hash digital add
		{
			printf("isRejectTransaction: Bet guess type [%u] invalid \n", iGuessType_bet);
			goto check_Complete;		
		}
		int iGenTxHei = GetTransactionBlockHeight(sLotteryLinkedTxid_gen);
		if( (iGenTxHei < BitNetLotteryStartTestBlock_286000) || (iBetTxHei < iGenTxHei) )
		{
			printf("isRejectTransaction: Genesis tx [%s] not exist or invalid, hei =[%u] \n", sLotteryLinkedTxid_gen.c_str(), iGenTxHei);
			goto check_Complete;
		}
		
//bool isValidLotteryGenesisTxs(const string& txID, int iTxHei, int iTargetGuessType, int iTargetGuessLen, int64_t i6TargetBlock, const string sTargetMaker, const string sTargetGenesisAddr)
		/* if( isValidLotteryGenesisTxs(sLotteryLinkedTxid_gen, iGenTxHei, iGuessType_bet, iKeyLen_bet, 0, sMakerAddr_cash, sLotteryAddr_bet) == false )
		{
			printf("Bet tx [%s] linked genesis tx [%s] not under rules :(\n", sLotteryBetTxid.c_str(), sLotteryLinkedTxid_gen.c_str());
			goto check_Complete;	
		} */	
		string sLotId_gen, sGuessTxt_gen, sLotteryAddr_gen, sLotteryPrivKey_gen, sMakerAddr_gen, sLotteryGenesisTxid_gen;
		int iLotteryType_gen, iGuessType_gen, iKeyLen_gen;
		int64_t iAmount_gen, iMiniBet_gen, iStartBlock_gen, iEndBlock_gen;			
// get linked Genesis tx info
		i = GetTxMsgParamS(sLotteryLinkedTxid_gen, sLotId_gen, iLotteryType_gen, iGuessType_gen, iAmount_gen, iMiniBet_gen, iStartBlock_gen, iEndBlock_gen, iKeyLen_gen,
									sGuessTxt_gen, sLotteryAddr_gen, sLotteryPrivKey_gen, sMakerAddr_gen, sLotteryGenesisTxid_gen, sSignMsg);					
		if( i < 15 )
		{
			printf("isRejectTransaction: Encash tx [%s] linked bet tx [%s] linked \n\t genesis tx [%s] invalid, params count < 15 \n", sCashTxHash.c_str(), sLotteryBetTxid.c_str(), sLotteryLinkedTxid_gen.c_str());
			goto check_Complete;
		}
		if( iLotteryType_gen != 1 )
		{
			printf("isRejectTransaction: [%s] not a genesis tx, invalid type \n", sLotteryLinkedTxid_gen.c_str());
			goto check_Complete;
		}
// is lottery Genesis tx
		if( iCashTxHei <= (iEndBlock_gen + iBitNetBlockMargin3) )
		{
			printf("isRejectTransaction: Encash tx [%s]'s hei [%u] must > [%I64u], please wait \n", sCashTxHash.c_str(), iCashTxHei, (int64_t)(iEndBlock_gen + iBitNetBlockMargin3));
			goto check_Complete;
		}
		//if( (iGenTxHei < iStartBlock_gen) || (iGenTxHei > iEndBlock) || (iEndBlock - iBitNetBlockMargin3)) )

		if( (iBetTxHei < iStartBlock_gen) || (iBetTxHei > (iEndBlock_gen - iBitNetBlockMargin3)) )
		{ 
				printf("isRejectTransaction: Bet tx [%s]'s Hei (%u) not under rules, invalid :(\n", sLotteryBetTxid.c_str(), iBetTxHei);
				goto check_Complete;
		}
		int64_t i6Mini = MIN_Lottery_Create_Amount;
		if( isBitNetLotteryRuleStart() ){ i6Mini = BitNet_Lottery_Create_Mini_Amount_5K; }
		if( iAmount_gen < i6Mini )	
		{
			printf("isRejectTransaction: Genesis tx Amount [%I64u] < lottery's mini value [%I64u] :(\n", (iAmount_gen / COIN), (i6Mini / COIN));
			goto check_Complete;
		}
		if( iAmount_bet < iMiniBet_gen )
		{
			printf("isRejectTransaction: bet amount [%I64u] < mini bet [%I64u] \n", (iAmount_bet / COIN), (iMiniBet_gen / COIN));
			goto check_Complete;
		}
		if( iGuessType_bet != iGuessType_gen )
		{
			printf("isRejectTransaction: bet type [%u] != genesis type [%u] \n", iGuessType_bet, iGuessType_gen);
			goto check_Complete;		
		}
		if( iKeyLen_bet != iKeyLen_gen )	// guess block's hash text
		{
			printf("isRejectTransaction: bet type [%u], bet hash len [%u] != genesis bet hash len [%u] \n", iGuessType_bet, iKeyLen_bet, iKeyLen_gen);
			goto check_Complete;
		}
		
		if( isValidPrivKeysAddress(sLotteryPrivKey_gen, sLotteryAddr_gen) == 0 )
		{
			printf("isRejectTransaction: Genesis lottery PrivKey [%s]'s PubKey != [%s] :(\n", sLotteryPrivKey_gen.c_str(), sLotteryAddr_gen.c_str()); 
			goto check_Complete;
		}
		
		if( GetCoinAddrInTxOutIndex(sLotteryLinkedTxid_gen, sLotteryAddr_gen, iAmount_gen) == -1 )	// Check Lottery Amount, =-1 is invalid
		{ 
			printf("isRejectTransaction: Genesis tx not include: [%I64u] coins sent to Genesis lottery address [%s] \n", (iAmount_gen / COIN), sLotteryAddr_gen.c_str());
			goto check_Complete;		
		}
		if( GetCoinAddrInTxOutIndex(sLotteryBetTxid, sLotteryAddr_gen, iAmount_bet) == -1 )
		{
			printf("isRejectTransaction: Bet tx not include: [%I64u] coins sent to Genesis lottery address [%s] \n", (iAmount_bet / COIN), sLotteryAddr_gen.c_str());
			goto check_Complete;				
		}
		
		sLotteryAnswer = getBlockNByteHashStrByType(iEndBlock_gen, iKeyLen_gen, iGuessType_gen);
		if( fDebug ){ printf("isRejectTransaction:  sLotteryAnswer = [%s], Bet txt = [%s] \n", sLotteryAnswer.c_str(), sGuessTxt_bet.c_str()); }
		if( sGuessTxt_bet != sLotteryAnswer )
		{
			printf("isRejectTransaction: Bet guess text [%s] != [%s], Type = [%u] \n", sGuessTxt_bet.c_str(), sLotteryAnswer.c_str(), iGuessType_gen);
			goto check_Complete;	
		}
// scan all of (iStartBlock_gen ~ iEndBlock_gen)'s block includes tx, find the "Bet Max" and "Bet first" bettor's address		
		if( getBetBiggerWinnerFromBlockRange(iStartBlock_gen, (iEndBlock_gen - iBitNetBlockMargin3), iKeyLen_gen, iGuessType_gen, sGuessTxt_bet, sLotteryAddr_gen, iAmount_bet, sRztBiggerAddr, i6RztBiggerValue) > 0 )
		{
			// someone guessed
			if( sRztBiggerAddr == sMakerAddr_cash )
			{
				bCasherIsWinner = true;
				sCashTxLinkedGenesisTx = sLotteryLinkedTxid_gen;
				if( fDebug ){ printf("isRejectTransaction: [%s] linked bet lottery's \n\t winner is Encasher [%s]\n", sCashTxHash.c_str(), sRztBiggerAddr.c_str()); }
			}else{ if( fDebug ){ printf("[%s] linked bet lottery's \n\t winner is [%s], not Encasher [%s] \n", sCashTxHash.c_str(), sRztBiggerAddr.c_str(), sMakerAddr_cash.c_str()); } }		
		}else{	// no one guessed, lottery creater is winner
			if( fDebug ){ printf("isRejectTransaction: [%s] linked bet lottery's winner != [%s]\n", sCashTxHash.c_str(), sMakerAddr_cash.c_str()); }
		}
		
	}else{ if( fDebug )printf("isRejectTransaction: [%s] not a lottery tx, params count [%u] < 15 \n", sCashTxHash.c_str(), i); }
	
check_Complete:
	if( fDebug ){ printf( "isRejectTransaction: check_Complete, bCasherIsWinner = [%u], tx.vin.size() = [%u],  \n\t sCashTxLinkedGenesisTx = [%s], sRztBiggerAddr = [%s], \n", bCasherIsWinner, tx.vin.size(), sCashTxLinkedGenesisTx.c_str(), sRztBiggerAddr.c_str() ); }
	int j = 0;
	BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        uint256 hashBlock = 0;
        CTransaction txPrev;
		j++;

        if( fDebug ){ printf( "isRejectTransaction: (%u) txin.prevout.n = [%u], \n", j, txin.prevout.n ); }
		if( GetTransaction(txin.prevout.hash, txPrev, hashBlock) )	// get the vin's previous transaction
		{  
			string sPrevTxMsg = txPrev.vpndata;
			CTxDestination source;
			string preTxAddress = "";
			string sPreTxHash = txPrev.GetHash().ToString();
			int iPreTxHei = GetTransactionBlockHeight(sPreTxHash);
			if( fDebug ){ printf( "isRejectTransaction: (%u) iPreTxHei = [%u],  sPreTxHash [%s] \n", j, iPreTxHei, sPreTxHash.c_str() ); }

            //if( sPrevTxMsg.length() > 13){  if( isFreezeTx(tx, iCashTxHei, txPrev, iPreTxHei, txin.prevout.n) ){ return true; }  }  // 2015.09.20 add

			if( iTxHei > 0 ){
#ifdef USE_BITNET 
				if( bServiceMode == 0 ){ 
					IsMonitorTx(txPrev.nTime, iPreTxHei, sPreTxHash, txPrev, txin.prevout.n); 
				}
#endif
			}
			
			if (ExtractDestination(txPrev.vout[txin.prevout.n].scriptPubKey, source))  
			{
                CBitcoinAddress addressSource(source);
				preTxAddress = addressSource.ToString();			
				//printf("isRejectTransaction: preTxAddress is [%s] : [%s]\n", preTxAddress.c_str(), sPrevTxMsg.c_str());
				int iPos = 0;
				if( isSoCoinAddress(tx, preTxAddress, iPos) > 0 )	//if (lostWallet.Get() == addressSource.Get())
				{
					if( fDebug ){ printf("isRejectTransaction: (%u) Send coin from [%s]  [%u], ban. \n********************\n\n\n", j, preTxAddress.c_str(), iPos); }
                    return true;
                }				
			}
			
			// check for lottery tx, only protect under rules lottery.
			string sLotId_Pre, sGuessTxt_Pre, sLotteryAddr_Pre, sLotteryPrivKey_Pre, sMakerAddr_Pre, sLotteryLinkedTxid_Pre, sSignMsg_Pre;
			int iLotteryType_Pre, iGuessType_Pre, iKeyLen_Pre;
			int64_t iAmount_Pre, iMiniBet_Pre, iStartBlock_Pre, iEndBlock_Pre;
		
			i = GetTxMsgParam(txPrev, sLotId_Pre, iLotteryType_Pre, iGuessType_Pre, iAmount_Pre, iMiniBet_Pre, iStartBlock_Pre, iEndBlock_Pre, iKeyLen_Pre, 
							sGuessTxt_Pre, sLotteryAddr_Pre, sLotteryPrivKey_Pre, sMakerAddr_Pre, sLotteryLinkedTxid_Pre, sSignMsg_Pre);			
			if( fDebug ){ printf("isRejectTransaction: (%u) iLotteryType_Pre = [%u], Hei = [%u], Prev Address = [%s], Prev Tx Hash = [%s], \n\t Tx Msg = [%s] \n", j, iLotteryType_Pre, iPreTxHei, preTxAddress.c_str(), sPreTxHash.c_str(), sPrevTxMsg.c_str()); }
			//if( (sPrevTxMsg.length() > 34) && (sPrevTxMsg.find(strBitNetLotteryMagic) == 0) )   //  "BitNet Lottery:"
			if( i < 15 )
			{ 
				if( fDebug ){ printf("isRejectTransaction: (%u) Prev Tx [%s] not a lottery tx, params count [%u] < 15, continue \n", j, sPreTxHash.c_str(), i); }
				continue;
			}

			bool bPreTxInIsTargetAddr = is_Txin_prevout_n_s_sendto_address(txin.prevout.hash, txin.prevout.n, sLotteryAddr_Pre);
			if( fDebug ){ printf( "isRejectTransaction: (%u) txin.prevout.n = [%u], bPreTxInIsTargetAddr = [%u] \n", j, txin.prevout.n, bPreTxInIsTargetAddr ); }
			if( !bPreTxInIsTargetAddr )
			{ 
				if( fDebug ){ printf( "isRejectTransaction: (%u) txin.prevout.n = [%u]'s address != sLotteryAddr_Pre (%s), continue \n", j, txin.prevout.n, sLotteryAddr_Pre.c_str() ); }
				continue; 
			}
// it's a lottery tx			
			bool bValidPayTx = false;
			int iPreTx_linked_Hei = GetTransactionBlockHeight(sLotteryLinkedTxid_Pre);	// genesis tx's sLotteryLinkedTxid_Pre is empt
			if( fDebug ){ printf("isRejectTransaction: (%u) iPreTx_linked_Hei = [%u],  iCashTxHei = [%u], sLotteryLinkedTxid_Pre [%s] \n", j, iPreTx_linked_Hei, iCashTxHei, sLotteryLinkedTxid_Pre.c_str()); }
			if( (iPreTxHei < BitNetLotteryStartTestBlock_286000) || (iCashTxHei <= iPreTxHei) )
			{ 
				if( fDebug )printf("isRejectTransaction: (%u) iPreTxHei = [%u] not under rules,  iCashTxHei = [%u], continue :(\n", j, iPreTxHei, iCashTxHei);
				continue; 
			}
			if( iLotteryType_Pre == 1 )	// genesis tx
			{
//bool isValidLotteryGenesisTx(const CTransaction& tx, int iTxHei, int iTargetGuessType, int iTargetGuessLen, int64_t i6TargetBlock, const string sTargetMaker, const string sTargetGenesisAddr)
				bValidPayTx = isValidLotteryGenesisTx(txPrev, iPreTxHei, -1, -1, 0, "", "");
			}
			else if( iLotteryType_Pre == 2 )	// bet tx
			{
//bool isValidLotteryBetTx(const CTransaction& tx, int iTxHei, int iTargetGuessType, int iTargetGuessLen, int64_t i6TargetBlock, const string sTargetMaker, const string sTargetGenesisAddr)
				bValidPayTx = isValidLotteryBetTx(txPrev, iPreTxHei, -1, -1, 0, "", "");
			}else{ 
				if( fDebug )printf("isRejectTransaction: (%u) unsupport lottery type [%u], continue \n", j, iLotteryType_Pre); 
				continue; 
			}
			
			if( fDebug ){ printf("isRejectTransaction: (%u) bValidPayTx = [%u], bCasherIsWinner = [%u] \n", j, bValidPayTx, bCasherIsWinner); }
			if( bCasherIsWinner == false )
			{
				if( bValidPayTx )
				{
					iWillBan++;
					if( fDebug )printf("isRejectTransaction: (%u) sMakerAddr_cash(%s) not lottery cash tx [%s] linked tx's winner, will ban. \n", j, sMakerAddr_cash.c_str(), sCashTxHash.c_str());
					if( isBitNetLotteryRuleStart() )
					{ 
						if( fDebug )printf("isRejectTransaction: (%u) isBitNetLotteryRuleStart, bCasherIsWinner = false, bValidPayTx = [%u], ban! \n*******************\n\n\n", j, bValidPayTx);
						return true; 
					}
				}else{ if( fDebug ){ printf("isRejectTransaction: (%u) bCasherIsWinner = false, bValidPayTx = false ... \n", j); } }
			}
			else{
				// sMakerAddr_cash is a winner, but it's all input lottery tx's winner? let's check it (check the lottery genesis tx).
				if( fDebug ){ printf("isRejectTransaction: (%u) bCasherIsWinner = true, bValidPayTx = [%u], iLotteryType_Pre = [%u] \n", j, bValidPayTx, iLotteryType_Pre); }
				if( bValidPayTx )
				{
					if( iLotteryType_Pre == 1 )	// genesis tx
					{
						if( sPreTxHash != sCashTxLinkedGenesisTx )
						{ 
							iWillBan++;
							if( fDebug )printf("isRejectTransaction: (%u) [%s] is genesis tx [%s]'s winner, but can't Encash other genesis tx [%s]'s, will ban. \n", j, sMakerAddr_cash.c_str(), sCashTxLinkedGenesisTx.c_str(), sPreTxHash.c_str());
							if( isBitNetLotteryRuleStart() )
							{
								if( fDebug ){ printf("[%s] end ********************\n\n\n", sCashTxHash.c_str()); }
								return true;
							}
						}
					}
					else if( iLotteryType_Pre == 2 )	// bet tx
					{
						if( sLotteryLinkedTxid_Pre != sCashTxLinkedGenesisTx )
						{
							iWillBan++;
							if( fDebug )printf("isRejectTransaction: (%u) [%s] is genesis tx [%s]'s winner, but can't Encash bet tx linked other genesis tx [%s]'s, will ban. \n", j, sMakerAddr_cash.c_str(), sCashTxLinkedGenesisTx.c_str(), sLotteryLinkedTxid_Pre.c_str());
							if( isBitNetLotteryRuleStart() )
							{
								if( fDebug ){ printf("[%s] end ********************\n\n\n", sCashTxHash.c_str()); }
								return true;
							}
						}
					}
				}else{ if( fDebug )printf("isRejectTransaction: (%u) bCasherIsWinner = true, bValidPayTx = false, iLotteryType_Pre = [%u],  continue\n", j, iLotteryType_Pre); }
			}
		}else{ if( fDebug )printf("isRejectTransaction: (%u) GetTransaction(txin.prevout.hash, txPrev, hashBlock) false, continue \n", j); }
	}
	if( fDebug ){ printf("isRejectTransaction: rzt = [%d], i Will Ban = [%u], bCashMsgSign = [%u], bCasherIsWinner = [%u] \n", rzt, iWillBan, bCashMsgSignOk, bCasherIsWinner); }
	if( fDebug ){ printf("[%s] end ********************\n\n\n", sCashTxHash.c_str()); }
	return rzt;
}

int getLotteryWinner(const CTransaction& tx, const string sTargetMaker, string& sRztWinner, string& sRztAnswer, int64_t& i6RztBet, const string sBetTxt = "")
{
	int rzt = 0;

	string sTxMsg = tx.vpndata;
	if( sTxMsg.length() < 34 ){ return rzt; }
	
	string sTxHash = tx.GetHash().ToString();
	int iTxHei = GetTransactionBlockHeight(sTxHash);
	if( iTxHei == 0 )
	{ 
		if( fDebug )printf("getLotteryWinner: tx's hei = [%u], set to nBestHeight [%u] \n", iTxHei, nBestHeight); 
		iTxHei = nBestHeight;  
	}
	
	string sLotId, sGuessTxt, sLotteryAddr, sLotteryPrivKey, sMakerAddr, sLotteryGenesisTxid, sSignMsg;
	int iLotteryType, iGuessType, iHashLen,  iTargetGuessType = 0;
	int64_t iAmount, iMiniBet = 0, iStartBlock = 0, iEndBlock = 0;
	
	int i = GetTxMsgParam(tx, sLotId, iLotteryType, iGuessType, iAmount, iMiniBet, iStartBlock, iEndBlock, iHashLen, sGuessTxt, sLotteryAddr, sLotteryPrivKey, sMakerAddr, sLotteryGenesisTxid, sSignMsg);
	if( i < 15 ){ return rzt; }
	
	bool bValidLottery = false;
	if( iLotteryType == 1 )	// is Genesis tx
	{
		if( isValidLotteryGenesisTx(tx, iTxHei, -1, -1, 0, "", "") == false )
		{
			printf("getLotteryWinner: Genesis tx [%s] not under rules :(\n", sTxHash.c_str());
		}else{ bValidLottery = true; }
	}
	else if( iLotteryType == 2 )	// is Bet tx
	{
//bool isValidLotteryBetTx(const CTransaction& tx, int iTxHei, int iTargetGuessType, int iTargetGuessLen, int64_t i6TargetBlock, const string sTargetMaker, const string sTargetGenesisAddr)
		if( isValidLotteryBetTx(tx, iTxHei, -1, -1, 0, "", "") == false )
		{
			printf("getLotteryWinner: Bet tx [%s] not under rules, will ban :(\n", sTxHash.c_str());
		}else{
			string sLotId_gen, sGuessTxt_gen, sLotteryAddr_gen, sLotteryPrivKey_gen, sMakerAddr_gen, sLotteryGenesisTxid_gen;
			int iLotteryType_gen, iGuessType_gen, iHashLen_gen;
			int64_t iAmount_gen, iMiniBet_gen, iStartBlock_gen, iEndBlock_gen;			
			// get linked Genesis tx info
			i = GetTxMsgParamS(sLotteryGenesisTxid, sLotId_gen, iLotteryType_gen, iGuessType_gen, iAmount_gen, iMiniBet_gen, iStartBlock_gen, iEndBlock_gen, iHashLen_gen,
									sGuessTxt_gen, sLotteryAddr_gen, sLotteryPrivKey_gen, sMakerAddr_gen, sLotteryGenesisTxid_gen, sSignMsg);		
			if( i < 15 ){ return rzt; }
			iGuessType = iGuessType_gen;   sGuessTxt = sGuessTxt_gen;  iStartBlock = iStartBlock_gen;   iEndBlock = iEndBlock_gen;   iHashLen = iHashLen_gen;
			iAmount = iAmount_gen;   iMiniBet = iMiniBet_gen;   sLotteryAddr = sLotteryAddr_gen;   sMakerAddr = sMakerAddr_gen;  bValidLottery = true;
		}
	}else{ printf("getLotteryWinner: [%s] not a Lottery tx, invalid type \n", sTxHash.c_str()); }
	
	if( !bValidLottery )
	{
		printf("getLotteryWinner: not a valid tx \n");
		return rzt;
	}
	
	if( nBestHeight < iEndBlock )	//if( nBestHeight <= (iEndBlock + iBitNetBlockMargin3) )
	{
		printf("getLotteryWinner: nBestHeight [%u] must >= [%I64u], please wait \n", nBestHeight, iEndBlock);
		return rzt;
	}
			
	string sLotteryAnswer = getBlockNByteHashStrByType(iEndBlock, iHashLen, iGuessType);
	//if( fDebug ){ printf("getLotteryWinner: sLotteryAnswer = [%s]", sLotteryAnswer.c_str()); }
	if( fDebug ){
		printf("getLotteryWinner: Hei [%u], [%I64u ~ %I64u], Hash Len [%u], Guess Type [%u], Answer [%s], Lottery gen addr [%s], Mini Bet [%I64u] \n", iTxHei, iStartBlock, iEndBlock, iHashLen, iGuessType, sLotteryAnswer.c_str(), sLotteryAddr.c_str(), (iMiniBet / COIN));
	}
	
	if( sLotteryAnswer.length() < 1 ){ return rzt; }
	sRztAnswer = sLotteryAnswer.c_str();
	string sRztBiggerAddr = "";
	int64_t i6RztBiggerValue = 0;
	// scan all of (iStartBlock ~ iEndBlock)'s block includes tx, find the "Bet Max" and "Bet first" bettor's address		
	if( getBetBiggerWinnerFromBlockRange(iStartBlock, (iEndBlock - iBitNetBlockMargin3), iHashLen, iGuessType, sLotteryAnswer, sLotteryAddr, iMiniBet, sRztBiggerAddr, i6RztBiggerValue) > 0 )
	{
		if( sTargetMaker.length() > 30 )	//if( validateAddress(sTargetMaker) )
		{
			if( sTargetMaker == sRztBiggerAddr ){ rzt++; }
		}else{ rzt++; }
		//if( rzt > 0 )
		{ sRztWinner = sRztBiggerAddr.c_str();   i6RztBet = i6RztBiggerValue; }
		if( (sBetTxt.length() > 0) && (sBetTxt != sLotteryAnswer) )
		{
			if( fDebug ){ printf("getLotteryWinner: BetTxt [%s] != [%s] \n", sBetTxt.c_str(), sGuessTxt.c_str()); }
			rzt = 0;
		}		
	}else{
		rzt = 2;	// lottery creator is the winner
		sRztWinner = sMakerAddr.c_str();   i6RztBet = iAmount;
	}
	return rzt;
}

bool isRejectTransaction(const string txID)
{
	bool rzt = false;
	if( txID.length() > 34 )
	{
		uint256 hash;
		hash.SetHex(txID);
		uint256 hashBlock = 0;
		CTransaction tx;
		if (!GetTransaction(hash, tx, hashBlock))
			return rzt;
		if( hashBlock == 0 ){ return rzt; }
		unsigned int iHi = 0;
        map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end() && (*mi).second)
        {
            CBlockIndex* pindex = (*mi).second;
            if( pindex->IsInMainChain() ){ iHi = pindex->nHeight; }
                //entry.push_back(Pair("confirmations", 1 + nBestHeight - pindex->nHeight));
        }
		rzt = isRejectTransaction(tx, iHi);
	}
	return rzt;
}

//isrejecttx 81c8fc595e4adceff9f0bde6588adc29be251aa51f264e5d1eef577eb41007c3
Value isrejecttx(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1)
        throw runtime_error(
            "isrejecttx <txid>\n"
            "Test for check valid of lottery <txid>");

    string sId = params[0].get_str();
	//printf("\n\n\n********************");
	bool i = isRejectTransaction(sId);
	//printf("********************\n\n\n");
    Object ret;
	ret.push_back( Pair("Tx id", sId) );
	ret.push_back( Pair("Result", i) );
    return ret;
}

Value rescanwtx(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1)
        throw runtime_error(
            "rescanwtx <block height>\n"
            "Rescan For Wallet Transactions from <block height>");

    unsigned int iHei = params[0].get_int();
	CBlockIndex* pStart = FindBlockByHeight(iHei);
	int i = 0;
	if( pStart )
	{
		i = pwalletMain->ScanForWalletTransactions(pStart, true);	//pindexGenesisBlock
		pwalletMain->ReacceptWalletTransactions();
	}
    Object ret;
	ret.push_back( Pair("Result", i) );
    return ret;
}

int getLotteryWinner(const string txID, const string sTargetMaker, string& sRztWinner, string& sRztAnswer, int64_t& i6RztBet, const string sBetTxt = "")
{
	int rzt = 0;
	sRztWinner = "";
	i6RztBet = 0;
	if( txID.length() > 34 )
	{
		uint256 hash;
		hash.SetHex(txID);
		uint256 hashBlock = 0;
		CTransaction tx;
		if (!GetTransaction(hash, tx, hashBlock))
			return rzt;
		if( hashBlock > 0 )
		{
			rzt = getLotteryWinner(tx, sTargetMaker, sRztWinner, sRztAnswer, i6RztBet, sBetTxt);
		}else{
			if( fDebug ){ printf("getLotteryWinner: hashBlock = [%s], invalid :( \n", hashBlock.ToString().c_str()); }
		}
	}
	return rzt;
}

//getlotterywinner 91b12f9f1961233ec9e2ddbbb3363b45d5b6a701bbbd8b332361a123b29cd343
Value getlotterywinner(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1)
        throw runtime_error(
            "getlotterywinner <txid> <coin address(not must fill)>\n"
            "Return lottery <txid>'s winner.");

    //int nBegin = params[0].get_int();
	string sTargetMaker = "";
	string sRztWinner = "", sRztAnswer = "";
	int64_t i6RztBet = 0;
    string sId = params[0].get_str();
	if( params.size() > 1 ){ sTargetMaker = params[0].get_str(); }
	int i = getLotteryWinner(sId, sTargetMaker, sRztWinner, sRztAnswer, i6RztBet);
	
    Object ret;
	ret.push_back( Pair("Is Winner", i) );
	//if( i > 0 )
	{
		ret.push_back( Pair("Winning number", sRztAnswer) );
		if( (i == 0) || (i == 1) ){ ret.push_back( Pair("Winner address", sRztWinner) ); }
		else if( i == 2 ){ ret.push_back( Pair("Winner is creator", sRztWinner) ); }
		ret.push_back( Pair("Bet amount", ValueFromAmount(i6RztBet)) );

		CTransaction tx;
		if( GetValidTransaction(sId, tx) > 0 )
		{
		string sAddr = GetTxMsgParamIndex(tx, 11);	// 11 = Lottery Address
		string sBHei = GetTxMsgParamIndex(tx, 7);
		string sTHei = GetTxMsgParamIndex(tx, 8);
		int nBegin = atof(sBHei.c_str());
		int nEnd = atof(sTHei.c_str());
		std::vector<std::pair<string, string> > entry;
		int64_t r6 = getBetAmountFromBlockRange(nBegin, nEnd, sAddr, &entry);

		ret.push_back(Pair("Betting List", ""));  //ret.push_back(Pair("Betting Count", entry.size()));
		BOOST_FOREACH(const PAIRTYPE(string, string)& item, entry)
		{
			ret.push_back(Pair(item.first, item.second));
		}
		}
	}
    return ret;
}



int  thisTxIndexSent(const CTransaction& tx, const string txID, unsigned int n)
{
	int rzt = 0;
	//int vsz = tx.vin.size();
	//if( vsz > 0 )
	int j = 0;
	string sTxHash = tx.GetHash().ToString();
	//if( fDebug ){ printf( "thisTxIndexSent: [%s], [%s], n = (%u) \n", sTxHash.c_str(), txID.c_str(), n ); }
	BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        uint256 hashBlock = 0;
        CTransaction txPrev;
		j++;

        //if( fDebug ){ printf( "thisTxIndexSent: [%s] (%u) txin.prevout.n = [%u]\n", txID.c_str(), j, txin.prevout.n ); }
		if( GetTransaction(txin.prevout.hash, txPrev, hashBlock) )	// get the vin's previous transaction
		{  
			string sPreTxHash = txPrev.GetHash().ToString();
			//if( fDebug ){ printf( "thisTxIndexSent: sPreTxHash = [%s] \n", sPreTxHash.c_str() ); }
			if( txID != sPreTxHash ){ continue; }
			
			if( txin.prevout.n == n )
			{
				rzt++;   
				if( fDebug ){ printf( "thisTxIndexSent: [%s], sPreTxHash = [%s], find n = %d, return \n", sTxHash.c_str(), sPreTxHash.c_str(), n ); }
				return rzt;
			}
		}
	}
	return rzt;
}

int scanTxIndexSentFromBlock(int nHeight, const string sTx, unsigned int n)
{
    int rzt = 0;
	if (nHeight < 0 ){ return rzt; }
	if( sTx.length() < 34 ){ return rzt; }
    CBlockIndex* pblockindex = FindBlockByHeight(nHeight);
	if( pblockindex )
	{
		CBlock block;
		block.ReadFromDisk(pblockindex);
		//int nHeight = pblockindex->nHeight;
			
		BOOST_FOREACH(const CTransaction& tx, block.vtx)
		{
			if (!IsFinalTx(tx, nHeight, block.GetBlockTime()))
			{
				if( fDebug ){ printf("scanTxIndexSentFromBlock: not FinalTx, return false :(\n"); }
				continue;		//return rzt;
			}
			
			if( thisTxIndexSent(tx, sTx, n) > 0 )
			{
				rzt++;
				if( fDebug ){ printf("scanTxIndexSentFromBlock: return [%d]\n", rzt); }
				return rzt;
			}
		}		
	}//else if( fDebug ){ printf("scanTxIndexSentFromBlock: pblockindex = NULL :(\n"); }
	return rzt;
}

//unsigned int get_SendToAddress_n_in_TxOut(const CTransaction& tx, const string sAddress)
unsigned int get_SendToAddress_n_in_TxOut(const string txID, const string sAddress)
{
	unsigned int rzt = 0;
	//string txID = tx.GetHash().ToString();  //prevoutHash.GetHex();
	if( fDebug ){ printf("get_SendToAddress_n_in_TxOut: tx id = [%s], Address [%s]\n", txID.c_str(), sAddress.c_str()); }
    CBitcoinAddress address(sAddress);
    if ( !address.IsValid() ){ return rzt; }
	
	CTransaction tx;
	if( GetValidTransaction(txID, tx) > 0 )
	{	
		//if( fDebug ){ printf("get_SendToAddress_n_in_TxOut: tx.vout.size() = [%u] \n", tx.vout.size()); }
		if( tx.vout.size() > 0 )
		{
			//BOOST_FOREACH(const CTxOut& txout, tx.vout)
			for (unsigned int i = 0; i < tx.vout.size(); i++)
			{
				const CTxOut& txout = tx.vout[i];
				txnouttype type;
				vector<CTxDestination> addresses;
				int nRequired;

				if( ExtractDestinations(txout.scriptPubKey, type, addresses, nRequired) )
				{
					BOOST_FOREACH(const CTxDestination& addr, addresses)
					{
						//rzt = strprintf("%s|%s", rzt.c_str(), CBitcoinAddress(addr).ToString().c_str());
						string sAa = CBitcoinAddress(addr).ToString();
						if( fDebug ){ printf("get_SendToAddress_n_in_TxOut: txout[%u].scriptPubKey's address = [%s]\n", i, sAa.c_str()); }
						if( sAa == sAddress )
						{
							if( fDebug ){ printf("get_SendToAddress_n_in_TxOut: result = [%d] :) \n", i); }
							return (i + 1);
						}
					}
				}
			}			
		}
	}
	return rzt;
}  //get_SendToAddress_n_in_TxOut

int is_Address_in_Tx_n_SentFromBlockRange(int iBlockBegin, int iBlockEnd, const string txID, const string sAddress)
{
	int rzt = 0;
	if( fDebug ){
		printf("scanTxIndexSentFromBlockRange: tx [%s], Address [%s]\n", txID.c_str(), sAddress.c_str());
	}
	if( iBlockEnd < iBlockBegin )
	{
		return rzt; 
	}
	
	unsigned int n = get_SendToAddress_n_in_TxOut(txID, sAddress);
	if( n <= 0 ){
		if( fDebug ){ printf("get_SendToAddress_n_in_TxOut: return %d :(\n", n); }
		return rzt; 
	}
	n = n - 1;

	for(int i = iBlockBegin; i <= iBlockEnd ; i++ )
	{
		if( scanTxIndexSentFromBlock(i, txID, n) > 0 )
		{
			rzt++;   break;
			//if( fDebug ){ printf("scanTxIndexSentFromBlockRange:  rzt = [%d] \n", sRztBiggerAddr.c_str(), (i6RztBiggerValue / COIN), rzt); }
		}
	}
	if( fDebug ){ printf("scanTxIndexSentFromBlockRange: rzt = %d, n = %d\n", rzt, n); }
	return rzt;	
}



Value sendtoaddresswithmsg(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
        throw runtime_error(
            "sendtoaddresswithmsg <vpncoinaddress> <amount> [message] [encrypt message]\n"
            "<amount> is a real and is rounded to the nearest 0.000001"
            + HelpRequiringPassphrase());

    CBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid VpnCoin address");

    // Amount
    int64_t nAmount = AmountFromValue(params[1]);

    // Wallet comments
    CWalletTx wtx;
    string stxData = "";
	int bEncrypt = 1;
    if (params.size() > 2 && params[2].type() != null_type && !params[2].get_str().empty())
        stxData = params[2].get_str();  //wtx.mapValue["comment"] = params[2].get_str();
	if (params.size() > 3 ){ bEncrypt = params[3].get_int(); }
    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

	string strError = pwalletMain->SendMoneyToDestination(address.Get(), nAmount, wtx, stxData, bEncrypt);
    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    return wtx.GetHash().GetHex();
}
