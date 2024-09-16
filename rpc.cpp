// Copyright (c) 2010 Satoshi Nakamoto
// Copytrigh (c) 2024 Makoto Sakuyama
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifdef _MSC_VER
#pragma warning(disable:4786)
#pragma warning(disable:4804)
#pragma warning(disable:4805)
#pragma warning(disable:4717)
#endif
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0400
#ifdef _WIN32_IE
#undef _WIN32_IE
#endif
#define _WIN32_IE 0x0400
#define WIN32_LEAN_AND_MEAN 1
#define __STDC_LIMIT_MACROS // to enable UINT64_MAX from stdint.h
#include <wx/wx.h>
#include <wx/stdpaths.h>
#include <wx/snglinst.h>
#if wxUSE_GUI
#include <wx/utils.h>
#include <wx/clipbrd.h>
#include <wx/taskbar.h>
#endif
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <db_cxx.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <limits.h>
#include <float.h>
#include <assert.h>
#include <memory>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <list>
#include <deque>
#include <map>
#include <set>
#include <algorithm>
#include <numeric>
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/tuple/tuple_io.hpp>
#include <boost/array.hpp>
#include <boost/bind.hpp>
#include <boost/function.hpp>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>

#ifdef __WXMSW__
#include <windows.h>
#include <winsock2.h>
#include <mswsock.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <io.h>
#include <process.h>
#include <malloc.h>
#else
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <ifaddrs.h>
#endif
#ifdef __BSD__
#include <netinet/in.h>
#endif


#pragma hdrstop
using namespace std;
using namespace boost;

#include "strlcpy.h"
#include "serialize.h"
#include "uint256.h"
#include "util.h"
#include "key.h"
#include "bignum.h"
#include "base58.h"
#include "script.h"
#include "db.h"
#include "net.h"
#include "main.h"
#include "rpc.h"
#if wxUSE_GUI
#include "uibase.h"
#endif
#include "ui.h"
#include "init.h"




//#include "headers.h"
#undef printf
#include <boost/asio.hpp>
#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"
#define printf OutputDebugStringF
// MinGW 3.4.5 gets "fatal error: had to relocate PCH" if the json headers are
// precompiled in headers.h.  The problem might be when the pch file goes over
// a certain size around 145MB.  If we need access to json_spirit outside this
// file, we could use the compiled json_spirit option.

using boost::asio::ip::tcp;
using namespace json_spirit;

void ThreadRPCServer2(void* parg);
typedef Value(*rpcfn_type)(const Array& params, bool fHelp);
extern map<string, rpcfn_type> mapCallTable;



Value help(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "help\n"
            "List commands.");

    string strRet;
    for (map<string, rpcfn_type>::iterator mi = mapCallTable.begin(); mi != mapCallTable.end(); ++mi)
    {
        try
        {
            Array params;
            (*(*mi).second)(params, true);
        }
        catch (std::exception& e)
        {
            // Help text is returned in an exception
            string strHelp = string(e.what());
            if (strHelp.find('\n') != -1)
                strHelp = strHelp.substr(0, strHelp.find('\n'));
            strRet += strHelp + "\n";
        }
    }
    strRet = strRet.substr(0,strRet.size()-1);
    return strRet;
}


Value stop(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "stop\n"
            "Stop alphacash server.");

    // Shutdown will take long enough that the response should get back
    CreateThread(Shutdown, NULL);
    return "alphacash server stopping";
}


Value getblockcount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getblockcount\n"
            "Returns the number of blocks in the longest block chain.");

    return nBestHeight + 1;
}


Value getblocknumber(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getblocknumber\n"
            "Returns the block number of the latest block in the longest block chain.");

    return nBestHeight;
}

//updated to show IP addresses
Value getconnectioncount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getconnectionaddresses\n"
            "Returns a list of IP addresses of the connections to other nodes.");

    Array connections;
    for (const CNode* pnode : vNodes)
    {
        connections.push_back(pnode->addr.ToStringIP());
    }

    return connections;
}

double GetDifficulty()
{
    // Floating point number that is a multiple of the minimum difficulty,
    // minimum difficulty = 1.0.
    if (pindexBest == NULL)
        return 1.0;
    
    //Extract the exponent from the compact representation
    int nShift = (pindexBest->nBits >> 24) & 0xff;
    // Calculate the initial difficulty using the new minimum difficulty target
    double dDiff = (double)0x0fffff / (double)(pindexBest->nBits & 0x00ffffff);
    // Adjust the difficulty based on the exponent difference
    while (nShift < 29)
    {
      dDiff *= 256.0;
      nShift++;
    }
    while (nShift > 29)
    {
      dDiff /= 256.0;
      nShift--;
    }
    return dDiff;
}

Value getdifficulty(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getdifficulty\n"
            "Returns the proof-of-work difficulty as a multiple of the minimum difficulty.");

    return GetDifficulty();
}


Value getbalance(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getbalance\n"
            "Returns the server's available balance.");

    return ((double)GetBalance() / (double)COIN);
}


Value getgenerate(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getgenerate\n"
            "Returns true or false.");

    return (bool)fGenerateAlphas;
}


Value setgenerate(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "setgenerate <generate> [genproclimit]\n"
            "<generate> is true or false to turn generation on or off.\n"
            "Generation is limited to [genproclimit] processors, -1 is unlimited.");

    bool fGenerate = true;
    if (params.size() > 0)
        fGenerate = params[0].get_bool();

    if (params.size() > 1)
    {
        int nGenProcLimit = params[1].get_int();
        fLimitProcessors = (nGenProcLimit != -1);
        CWalletDB().WriteSetting("fLimitProcessors", fLimitProcessors);
        if (nGenProcLimit != -1)
            CWalletDB().WriteSetting("nLimitProcessors", nLimitProcessors = nGenProcLimit);
    }

    GenerateAlphas(fGenerate);
    return Value::null;
}


int extract_private_key_from_hex_der(const CPrivKey& privKey, char** hex_private_key) {
    // Convert CPrivKey to binary (which it already is)
    size_t der_len = privKey.size();
    const unsigned char* der_key = &privKey[0];
    
    // Print the size of the DER-encoded private key
    std::cout << "DER-encoded private key size: " << der_len << " bytes" << std::endl;

    // Deserialize the DER-encoded EC private key
    EC_KEY* ec_key = NULL;
    const unsigned char* p = der_key;
    ec_key = d2i_ECPrivateKey(NULL, &p, der_len);
    if (ec_key == NULL) {
        fprintf(stderr, "Failed to deserialize EC private key.\n");
        return 1;
    }

    // Extract the private key as a BIGNUM
    const BIGNUM* bn_private_key = EC_KEY_get0_private_key(ec_key);
    if (bn_private_key == NULL) {
        fprintf(stderr, "Failed to extract private key.\n");
        EC_KEY_free(ec_key);
        return 1;
    }
    
    // Get the size of the private key in bytes
       int private_key_size = BN_num_bytes(bn_private_key);
       std::cout << "Private key size (BIGNUM): " << private_key_size << " bytes" << std::endl;

    // Ensure private key is always 32 bytes (pad with leading zeroes if necessary)
    unsigned char priv_key_bytes[32] = {0};  // Initialize all bytes to 0
    int num_bytes = BN_bn2bin(bn_private_key, priv_key_bytes + (32 - private_key_size));

    // Convert the 32-byte private key to a hexadecimal string
    *hex_private_key = (char*)OPENSSL_malloc(65);  // 32 bytes in hex (64 characters) + null terminator
    if (*hex_private_key == NULL) {
        fprintf(stderr, "Failed to allocate memory for hex private key.\n");
        EC_KEY_free(ec_key);
        return 1;
    }

    // Convert each byte to its hexadecimal representation
    for (int i = 0; i < 32; i++) {
        sprintf(*hex_private_key + (i * 2), "%02x", priv_key_bytes[i]);
    }
    (*hex_private_key)[64] = '\0';  // Null-terminate the string

    std::cout << "Private Key (Hex): " << *hex_private_key << std::endl;

    // Free the memory
    EC_KEY_free(ec_key);

    return 0; // Success
}


Value printkeys(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "printkeys");
    

    
    // Get the full path to the "keys.dat" file in the data directory
    std::string filePath = GetDataDir() + "/keys.dat";

    
    // Open the file for writing (overwrites if the file exists)
    FILE* outFile = fopen(filePath.c_str(), "w");
    if (outFile == NULL) {
     std::cerr << "Error: Unable to open file " << filePath << " for writing.\n";
        return Value::null;
    }

    // Write header to the file
//    fprintf(outFile, "Printing all keys in the wallet:\n");
    
    CRITICAL_BLOCK(cs_mapKeys)
    {
        for (const auto& keyPair : mapKeys)
        {
            const vector<unsigned char>& pubKey = keyPair.first;     // Public key
            const CPrivKey& privKey = keyPair.second;                // Private key
            
            // Check if the public key is either 33 bytes (compressed) or 65 bytes (uncompressed)
            if (pubKey.size() == 33 || (pubKey.size() == 65 && pubKey[0] == 0x04)) {
//                fprintf(outFile, "Public Key: %s\n", HexStr(pubKey).c_str());
            } else {
                fprintf(outFile, "Invalid public key length or format! Public Key size: %zu\n", pubKey.size());
                return Value::null;
            }
            
            // Extract Private key from DER encoding
            char* hex_private_key = NULL;
            int result = extract_private_key_from_hex_der(privKey, &hex_private_key);
            if (result == 0) {
                fprintf(outFile, "%s\n", hex_private_key);
                
                // Calculate the size of the private key
                size_t hex_private_key_length = strlen(hex_private_key);
                size_t private_key_size = hex_private_key_length / 2;  // Each byte is 2 hex chars
//                fprintf(outFile, "Private Key Size: %zu bytes\n", private_key_size);
            }
            
            // Free the private key after use
            if (hex_private_key != NULL) {
                OPENSSL_free(hex_private_key);
            }
        }
    }
    fclose(outFile);
    return Value::null;
    
}

Value getinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getinfo");

    Object obj;
    obj.push_back(Pair("balance",       (double)GetBalance() / (double)COIN));
    obj.push_back(Pair("blocks",        (int)nBestHeight + 1));
    obj.push_back(Pair("connections",   (int)vNodes.size()));
    obj.push_back(Pair("proxy",         (fUseProxy ? addrProxy.ToStringIPPort() : string())));
    obj.push_back(Pair("generate",      (bool)fGenerateAlphas));
    obj.push_back(Pair("genproclimit",  (int)(fLimitProcessors ? nLimitProcessors : -1)));
    obj.push_back(Pair("difficulty",    (double)GetDifficulty()));
    return obj;
}


Value getnewaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getnewaddress [label]\n"
            "Returns a new alphacash address for receiving payments.  "
            "If [label] is specified (recommended), it is added to the address book "
            "so payments received with the address will be labeled.");

    // Parse the label first so we don't generate a key if there's an error
    string strLabel;
    if (params.size() > 0)
        strLabel = params[0].get_str();

    // Generate a new key that is added to wallet
    string strAddress = PubKeyToAddress(GenerateNewKey());

    SetAddressBookName(strAddress, strLabel);
    return strAddress;
}


Value setlabel(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "setlabel <alphacashaddress> <label>\n"
            "Sets the label associated with the given address.");

    string strAddress = params[0].get_str();
    string strLabel;
    if (params.size() > 1)
        strLabel = params[1].get_str();

    SetAddressBookName(strAddress, strLabel);
    return Value::null;
}


Value getlabel(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getlabel <alphacashaddress>\n"
            "Returns the label associated with the given address.");

    string strAddress = params[0].get_str();

    string strLabel;
    CRITICAL_BLOCK(cs_mapAddressBook)
    {
        map<string, string>::iterator mi = mapAddressBook.find(strAddress);
        if (mi != mapAddressBook.end() && !(*mi).second.empty())
            strLabel = (*mi).second;
    }
    return strLabel;
}


Value getaddressesbylabel(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaddressesbylabel <label>\n"
            "Returns the list of addresses with the given label.");

    string strLabel = params[0].get_str();

    // Find all addresses that have the given label
    Array ret;
    CRITICAL_BLOCK(cs_mapAddressBook)
    {
        foreach(const PAIRTYPE(string, string)& item, mapAddressBook)
        {
            const string& strAddress = item.first;
            const string& strName = item.second;
            if (strName == strLabel)
            {
                // We're only adding valid alphacash addresses and not ip addresses
                CScript scriptPubKey;
                if (scriptPubKey.SetAlphacashAddress(strAddress))
                    ret.push_back(strAddress);
            }
        }
    }
    return ret;
}


Value sendtoaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
        throw runtime_error(
            "sendtoaddress <alphacashaddress> <amount> [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest 0.01");

    string strAddress = params[0].get_str();

    // Amount
    if (params[1].get_real() <= 0.0 || params[1].get_real() > 21000000.0)
        throw runtime_error("Invalid amount");
    int64 nAmount = roundint64(params[1].get_real() * 100.00) * CENT;

    // Wallet comments
    CWalletTx wtx;
    if (params.size() > 2 && params[2].type() != null_type && !params[2].get_str().empty())
        wtx.mapValue["message"] = params[2].get_str();
    if (params.size() > 3 && params[3].type() != null_type && !params[3].get_str().empty())
        wtx.mapValue["to"]      = params[3].get_str();

    string strError = SendMoneyToAlphacashAddress(strAddress, nAmount, wtx);
    if (strError != "")
        throw runtime_error(strError);
    return "sent";
}


Value listtransactions(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "listtransactions [count=10] [includegenerated=false]\n"
            "Returns up to [count] most recent transactions.");

    int64 nCount = 10;
    if (params.size() > 0)
        nCount = params[0].get_int64();
    bool fGenerated = false;
    if (params.size() > 1)
        fGenerated = params[1].get_bool();

    Array ret;
    //// not finished
    ret.push_back("not implemented yet");
    return ret;
}


Value getreceivedbyaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getreceivedbyaddress <alphacashaddress> [minconf=1]\n"
            "Returns the total amount received by <alphacashaddress> in transactions with at least [minconf] confirmations.");

    // Alphacash address
    string strAddress = params[0].get_str();
    CScript scriptPubKey;
    if (!scriptPubKey.SetAlphacashAddress(strAddress))
        throw runtime_error("Invalid alphacash address");
    if (!IsMine(scriptPubKey))
        return (double)0.0;

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();

    // Tally
    int64 nAmount = 0;
    CRITICAL_BLOCK(cs_mapWallet)
    {
        for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx& wtx = (*it).second;
            if (wtx.IsCoinBase() || !wtx.IsFinal())
                continue;

            foreach(const CTxOut& txout, wtx.vout)
                if (txout.scriptPubKey == scriptPubKey)
                    if (wtx.GetDepthInMainChain() >= nMinDepth)
                        nAmount += txout.nValue;
        }
    }

    return (double)nAmount / (double)COIN;
}


Value getreceivedbylabel(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getreceivedbylabel <label> [minconf=1]\n"
            "Returns the total amount received by addresses with <label> in transactions with at least [minconf] confirmations.");

    // Get the set of pub keys that have the label
    string strLabel = params[0].get_str();
    set<CScript> setPubKey;
    CRITICAL_BLOCK(cs_mapAddressBook)
    {
        foreach(const PAIRTYPE(string, string)& item, mapAddressBook)
        {
            const string& strAddress = item.first;
            const string& strName = item.second;
            if (strName == strLabel)
            {
                // We're only counting our own valid alphacash addresses and not ip addresses
                CScript scriptPubKey;
                if (scriptPubKey.SetAlphacashAddress(strAddress))
                    if (IsMine(scriptPubKey))
                        setPubKey.insert(scriptPubKey);
            }
        }
    }

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();

    // Tally
    int64 nAmount = 0;
    CRITICAL_BLOCK(cs_mapWallet)
    {
        for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx& wtx = (*it).second;
            if (wtx.IsCoinBase() || !wtx.IsFinal())
                continue;

            foreach(const CTxOut& txout, wtx.vout)
                if (setPubKey.count(txout.scriptPubKey))
                    if (wtx.GetDepthInMainChain() >= nMinDepth)
                        nAmount += txout.nValue;
        }
    }

    return (double)nAmount / (double)COIN;
}


struct tallyitem
{
    int64 nAmount;
    int nConf;
    tallyitem()
    {
        nAmount = 0;
        nConf = INT_MAX;
    }
};

Value ListReceived(const Array& params, bool fByLabels)
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
    map<uint160, tallyitem> mapTally;
    CRITICAL_BLOCK(cs_mapWallet)
    {
        for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx& wtx = (*it).second;
            if (wtx.IsCoinBase() || !wtx.IsFinal())
                continue;

            int nDepth = wtx.GetDepthInMainChain();
            if (nDepth < nMinDepth)
                continue;

            foreach(const CTxOut& txout, wtx.vout)
            {
                // Only counting our own alphacash addresses and not ip addresses
                uint160 hash160 = txout.scriptPubKey.GetAlphacashAddressHash160();
                if (hash160 == 0 || !mapPubKeys.count(hash160)) // IsMine
                    continue;

                tallyitem& item = mapTally[hash160];
                item.nAmount += txout.nValue;
                item.nConf = min(item.nConf, nDepth);
            }
        }
    }

    // Reply
    Array ret;
    map<string, tallyitem> mapLabelTally;
    CRITICAL_BLOCK(cs_mapAddressBook)
    {
        foreach(const PAIRTYPE(string, string)& item, mapAddressBook)
        {
            const string& strAddress = item.first;
            const string& strLabel = item.second;
            uint160 hash160;
            if (!AddressToHash160(strAddress, hash160))
                continue;
            map<uint160, tallyitem>::iterator it = mapTally.find(hash160);
            if (it == mapTally.end() && !fIncludeEmpty)
                continue;

            int64 nAmount = 0;
            int nConf = INT_MAX;
            if (it != mapTally.end())
            {
                nAmount = (*it).second.nAmount;
                nConf = (*it).second.nConf;
            }

            if (fByLabels)
            {
                tallyitem& item = mapLabelTally[strLabel];
                item.nAmount += nAmount;
                item.nConf = min(item.nConf, nConf);
            }
            else
            {
                Object obj;
                obj.push_back(Pair("address",       strAddress));
                obj.push_back(Pair("label",         strLabel));
                obj.push_back(Pair("amount",        (double)nAmount / (double)COIN));
                obj.push_back(Pair("confirmations", (nConf == INT_MAX ? 0 : nConf)));
                ret.push_back(obj);
            }
        }
    }

    if (fByLabels)
    {
        for (map<string, tallyitem>::iterator it = mapLabelTally.begin(); it != mapLabelTally.end(); ++it)
        {
            int64 nAmount = (*it).second.nAmount;
            int nConf = (*it).second.nConf;
            Object obj;
            obj.push_back(Pair("label",         (*it).first));
            obj.push_back(Pair("amount",        (double)nAmount / (double)COIN));
            obj.push_back(Pair("confirmations", (nConf == INT_MAX ? 0 : nConf)));
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
            "  \"label\" : the label of the receiving address\n"
            "  \"amount\" : total amount received by the address\n"
            "  \"confirmations\" : number of confirmations of the most recent transaction included");

    return ListReceived(params, false);
}

Value listreceivedbylabel(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "listreceivedbylabel [minconf=1] [includeempty=false]\n"
            "[minconf] is the minimum number of confirmations before payments are included.\n"
            "[includeempty] whether to include labels that haven't received any payments.\n"
            "Returns an array of objects containing:\n"
            "  \"label\" : the label of the receiving addresses\n"
            "  \"amount\" : total amount received by addresses with this label\n"
            "  \"confirmations\" : number of confirmations of the most recent transaction included");

    return ListReceived(params, true);
}


//
// Call Table
//

pair<string, rpcfn_type> pCallTable[] =
{
    make_pair("help",                  &help),
    make_pair("stop",                  &stop),
    make_pair("getblockcount",         &getblockcount),
    make_pair("getblocknumber",        &getblocknumber),
    make_pair("getconnectioncount",    &getconnectioncount),
    make_pair("getdifficulty",         &getdifficulty),
    make_pair("getbalance",            &getbalance),
    make_pair("getgenerate",           &getgenerate),
    make_pair("setgenerate",           &setgenerate),
    make_pair("getinfo",               &getinfo),
    make_pair("getnewaddress",         &getnewaddress),
    make_pair("setlabel",              &setlabel),
    make_pair("getlabel",              &getlabel),
    make_pair("getaddressesbylabel",   &getaddressesbylabel),
    make_pair("sendtoaddress",         &sendtoaddress),
    make_pair("listtransactions",      &listtransactions),
    make_pair("getamountreceived",     &getreceivedbyaddress), // deprecated, renamed to getreceivedbyaddress
    make_pair("getallreceived",        &listreceivedbyaddress), // deprecated, renamed to listreceivedbyaddress
    make_pair("getreceivedbyaddress",  &getreceivedbyaddress),
    make_pair("getreceivedbylabel",    &getreceivedbylabel),
    make_pair("listreceivedbyaddress", &listreceivedbyaddress),
    make_pair("listreceivedbylabel",   &listreceivedbylabel),
    make_pair("printkeys",             &printkeys),
};


map<string, rpcfn_type> mapCallTable(pCallTable, pCallTable + sizeof(pCallTable)/sizeof(pCallTable[0]));




//
// HTTP protocol
//
// This ain't Apache.  We're just using HTTP header for the length field
// and to be compatible with other JSON-RPC implementations.
//

string HTTPPost(const string& strMsg)
{
    return strprintf(
            "POST / HTTP/1.1\r\n"
            "User-Agent: json-rpc/1.0\r\n"
            "Host: 127.0.0.1\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %d\r\n"
            "Accept: application/json\r\n"
            "\r\n"
            "%s",
        strMsg.size(),
        strMsg.c_str());
}

string HTTPReply(const string& strMsg, int nStatus=200)
{
    string strStatus;
    if (nStatus == 200) strStatus = "OK";
    if (nStatus == 500) strStatus = "Internal Server Error";
    return strprintf(
            "HTTP/1.1 %d %s\r\n"
            "Connection: close\r\n"
            "Content-Length: %d\r\n"
            "Content-Type: application/json\r\n"
            "Date: Sat, 08 Jul 2006 12:04:08 GMT\r\n"
            "Server: json-rpc/1.0\r\n"
            "\r\n"
            "%s",
        nStatus,
        strStatus.c_str(),
        strMsg.size(),
        strMsg.c_str());
}

int ReadHTTPHeader(tcp::iostream& stream)
{
    int nLen = 0;
    loop
    {
        string str;
        std::getline(stream, str);
        if (str.empty() || str == "\r")
            break;
        if (str.substr(0,15) == "Content-Length:")
            nLen = atoi(str.substr(15));
    }
    return nLen;
}

inline string ReadHTTP(tcp::iostream& stream)
{
    // Read header
    int nLen = ReadHTTPHeader(stream);
    if (nLen <= 0)
        return string();

    // Read message
    vector<char> vch(nLen);
    stream.read(&vch[0], nLen);
    return string(vch.begin(), vch.end());
}



//
// JSON-RPC protocol
//
// http://json-rpc.org/wiki/specification
// http://www.codeproject.com/KB/recipes/JSON_Spirit.aspx
//

string JSONRPCRequest(const string& strMethod, const Array& params, const Value& id)
{
    Object request;
    request.push_back(Pair("method", strMethod));
    request.push_back(Pair("params", params));
    request.push_back(Pair("id", id));
    return write_string(Value(request), false) + "\n";
}

string JSONRPCReply(const Value& result, const Value& error, const Value& id)
{
    Object reply;
    if (error.type() != null_type)
        reply.push_back(Pair("result", Value::null));
    else
        reply.push_back(Pair("result", result));
    reply.push_back(Pair("error", error));
    reply.push_back(Pair("id", id));
    return write_string(Value(reply), false) + "\n";
}




void ThreadRPCServer(void* parg)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadRPCServer(parg));
    try
    {
        vnThreadsRunning[4]++;
        ThreadRPCServer2(parg);
        vnThreadsRunning[4]--;
    }
    catch (std::exception& e) {
        vnThreadsRunning[4]--;
        PrintException(&e, "ThreadRPCServer()");
    } catch (...) {
        vnThreadsRunning[4]--;
        PrintException(NULL, "ThreadRPCServer()");
    }
    printf("ThreadRPCServer exiting\n");
}

void ThreadRPCServer2(void* parg)
{
    printf("ThreadRPCServer started\n");

    // Bind to loopback 127.0.0.1 so the socket can only be accessed locally
    boost::asio::io_service io_service;
    tcp::endpoint endpoint(boost::asio::ip::address_v4::loopback(), 8332);
    tcp::acceptor acceptor(io_service, endpoint);

    loop
    {
        // Accept connection
        tcp::iostream stream;
        tcp::endpoint peer;
        vnThreadsRunning[4]--;
        acceptor.accept(*stream.rdbuf(), peer);
        vnThreadsRunning[4]++;
        if (fShutdown)
            return;

        // Shouldn't be possible for anyone else to connect, but just in case
        if (peer.address().to_string() != "127.0.0.1")
            continue;

        // Receive request
        string strRequest = ReadHTTP(stream);
        printf("ThreadRPCServer request=%s", strRequest.c_str());

        // Handle multiple invocations per request
        string::iterator begin = strRequest.begin();
        while (skipspaces(begin), begin != strRequest.end())
        {
            string::iterator prev = begin;
            Value id;
            try
            {
                // Parse request
                Value valRequest;
                if (!read_range(begin, strRequest.end(), valRequest))
                    throw runtime_error("Parse error.");
                const Object& request = valRequest.get_obj();
                if (find_value(request, "method").type() != str_type ||
                    find_value(request, "params").type() != array_type)
                    throw runtime_error("Invalid request.");

                string strMethod    = find_value(request, "method").get_str();
                const Array& params = find_value(request, "params").get_array();
                id                  = find_value(request, "id");

                // Execute
                map<string, rpcfn_type>::iterator mi = mapCallTable.find(strMethod);
                if (mi == mapCallTable.end())
                    throw runtime_error("Method not found.");
                Value result = (*(*mi).second)(params, false);

                // Send reply
                string strReply = JSONRPCReply(result, Value::null, id);
                stream << HTTPReply(strReply, 200) << std::flush;
            }
            catch (std::exception& e)
            {
                // Send error reply
                string strReply = JSONRPCReply(Value::null, e.what(), id);
                stream << HTTPReply(strReply, 500) << std::flush;
            }
            if (begin == prev)
                break;
        }
    }
}




Value CallRPC(const string& strMethod, const Array& params)
{
    // Connect to localhost
    tcp::iostream stream("127.0.0.1", "8332");
    if (stream.fail())
        throw runtime_error("couldn't connect to server");

    // Send request
    string strRequest = JSONRPCRequest(strMethod, params, 1);
    stream << HTTPPost(strRequest) << std::flush;

    // Receive reply
    string strReply = ReadHTTP(stream);
    if (strReply.empty())
        throw runtime_error("no response from server");

    // Parse reply
    Value valReply;
    if (!read_string(strReply, valReply))
        throw runtime_error("couldn't parse reply from server");
    const Object& reply = valReply.get_obj();
    if (reply.empty())
        throw runtime_error("expected reply to have result, error and id properties");

    const Value& result = find_value(reply, "result");
    const Value& error  = find_value(reply, "error");
    const Value& id     = find_value(reply, "id");

    if (error.type() == str_type)
        throw runtime_error(error.get_str());
    else if (error.type() != null_type)
        throw runtime_error(write_string(error, false));
    return result;
}




template<typename T>
void ConvertTo(Value& value)
{
    if (value.type() == str_type)
    {
        // reinterpret string as unquoted json value
        Value value2;
        if (!read_string(value.get_str(), value2))
            throw runtime_error("type mismatch");
        value = value2.get_value<T>();
    }
    else
    {
        value = value.get_value<T>();
    }
}

int CommandLineRPC(int argc, char *argv[])
{
    try
    {
        // Check that method exists
        if (argc < 2)
            throw runtime_error("too few parameters");
        string strMethod = argv[1];
        if (!mapCallTable.count(strMethod))
            throw runtime_error(strprintf("unknown command: %s", strMethod.c_str()));

        Value result;
        if (argc == 3 && strcmp(argv[2], "-?") == 0)
        {
            // Call help locally, help text is returned in an exception
            try
            {
                map<string, rpcfn_type>::iterator mi = mapCallTable.find(strMethod);
                Array params;
                (*(*mi).second)(params, true);
            }
            catch (std::exception& e)
            {
                result = e.what();
            }
        }
        else
        {
            // Parameters default to strings
            Array params;
            for (int i = 2; i < argc; i++)
                params.push_back(argv[i]);
            int n = params.size();

            //
            // Special case non-string parameter types
            //
            if (strMethod == "setgenerate"            && n > 0) ConvertTo<bool>(params[0]);
            if (strMethod == "setgenerate"            && n > 1) ConvertTo<boost::int64_t>(params[1]);
            if (strMethod == "sendtoaddress"          && n > 1) ConvertTo<double>(params[1]);
            if (strMethod == "listtransactions"       && n > 0) ConvertTo<boost::int64_t>(params[0]);
            if (strMethod == "listtransactions"       && n > 1) ConvertTo<bool>(params[1]);
            if (strMethod == "getamountreceived"      && n > 1) ConvertTo<boost::int64_t>(params[1]); // deprecated
            if (strMethod == "getreceivedbyaddress"   && n > 1) ConvertTo<boost::int64_t>(params[1]);
            if (strMethod == "getreceivedbylabel"     && n > 1) ConvertTo<boost::int64_t>(params[1]);
            if (strMethod == "getallreceived"         && n > 0) ConvertTo<boost::int64_t>(params[0]); // deprecated
            if (strMethod == "getallreceived"         && n > 1) ConvertTo<bool>(params[1]);
            if (strMethod == "listreceivedbyaddress"  && n > 0) ConvertTo<boost::int64_t>(params[0]);
            if (strMethod == "listreceivedbyaddress"  && n > 1) ConvertTo<bool>(params[1]);
            if (strMethod == "listreceivedbylabel"    && n > 0) ConvertTo<boost::int64_t>(params[0]);
            if (strMethod == "listreceivedbylabel"    && n > 1) ConvertTo<bool>(params[1]);

            // Execute
            result = CallRPC(strMethod, params);
        }

        // Print result
        string strResult = (result.type() == str_type ? result.get_str() : write_string(result, true));
        if (result.type() != null_type)
        {
            if (fWindows && fGUI)
                // Windows GUI apps can't print to command line,
                // so settle for a message box yuck
                MyMessageBox(strResult.c_str(), "Alphacash", wxOK);
            else
                fprintf(stdout, "%s\n", strResult.c_str());
        }
        return 0;
    }
    catch (std::exception& e) {
        if (fWindows && fGUI)
            MyMessageBox(strprintf("error: %s\n", e.what()).c_str(), "Alphacash", wxOK);
        else
            fprintf(stderr, "error: %s\n", e.what());
    } catch (...) {
        PrintException(NULL, "CommandLineRPC()");
    }
    return 1;
}




#ifdef TEST
int main(int argc, char *argv[])
{
#ifdef _MSC_VER
    // Turn off microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFile("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0));
#endif
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    try
    {
        if (argc >= 2 && string(argv[1]) == "-server")
        {
            printf("server ready\n");
            ThreadRPCServer(NULL);
        }
        else
        {
            return CommandLineRPC(argc, argv);
        }
    }
    catch (std::exception& e) {
        PrintException(&e, "main()");
    } catch (...) {
        PrintException(NULL, "main()");
    }
    return 0;
}
#endif
