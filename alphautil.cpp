// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2024 Makoto Sakuyama
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstdint>
#include <array>
#include <numeric>
#include <sha.h>
#include "headers.h"

// Function to convert Unix timestamp to human-readable format with timezone offset
std::string formatTimestamp(uint32_t timestamp) {
    std::time_t time = static_cast<std::time_t>(timestamp);
    std::tm* local_tm = std::localtime(&time);
    std::tm* utc_tm = std::gmtime(&time);

    // Calculate the timezone offset
    int local_hour = local_tm->tm_hour;
    int utc_hour = utc_tm->tm_hour;
    int timezone_offset = local_hour - utc_hour;

    // Adjust for day wrap-arounds
    if (timezone_offset < -12) {
        timezone_offset += 24;
    } else if (timezone_offset > 12) {
        timezone_offset -= 24;
    }

    // Format the timestamp
    std::stringstream ss;
    ss << std::put_time(local_tm, "%Y-%m-%d %H:%M:%S");

    // Add the timezone offset
    if (timezone_offset >= 0) {
        ss << " UTC+" << timezone_offset;
    } else {
        ss << " UTC" << timezone_offset;
    }

    return ss.str();
}

int FormatHashBlocks(void* pbuffer, unsigned int len);


using CryptoPP::ByteReverse;
static int detectlittleendian = 1;

void BlockSHA256(const void* pin, unsigned int nBlocks, void* pout)
{
    unsigned int* pinput = (unsigned int*)pin;
    unsigned int* pstate = (unsigned int*)pout;

    CryptoPP::SHA256::InitState(pstate);

    if (*(char*)&detectlittleendian != 0)
    {
        for (int n = 0; n < nBlocks; n++)
        {
            unsigned int pbuf[16];
            for (int i = 0; i < 16; i++)
                pbuf[i] = ByteReverse(pinput[n * 16 + i]);
            CryptoPP::SHA256::Transform(pstate, pbuf);
        }
        for (int i = 0; i < 8; i++)
            pstate[i] = ByteReverse(pstate[i]);
    }
    else
    {
        for (int n = 0; n < nBlocks; n++)
            CryptoPP::SHA256::Transform(pstate, pinput + n * 16);
    }
}

int FormatHashBlocks(void* pbuffer, unsigned int len)
{
    unsigned char* pdata = (unsigned char*)pbuffer;
    unsigned int blocks = 1 + ((len + 8) / 64);
    unsigned char* pend = pdata + 64 * blocks;
    memset(pdata + len, 0, 64 * blocks - len);
    pdata[len] = 0x80;
    unsigned int bits = len * 8;
    pend[-1] = (bits >> 0) & 0xff;
    pend[-2] = (bits >> 8) & 0xff;
    pend[-3] = (bits >> 16) & 0xff;
    pend[-4] = (bits >> 24) & 0xff;
    return blocks;
}


void RegenerateGenesisBlock()
{

        // Genesis block
        const char* pszTimestamp = "Financial Times 25/May/2024 What went wrong with capitalism";
        CTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 10 * COIN;
        CBigNum bnPubKey;
         bnPubKey.SetHex("0x5F1DF16B2B704C8A578D0BBAF74D385CDE12C11EE50455F3C438EF4C3FBCF649B6DE611FEAE06279A60939E028A8D65C10B73071A6F16719274855FEB0FD8A6704");
    
        txNew.vout[0].scriptPubKey = CScript() << bnPubKey << OP_CHECKSIG;
        
        CBlock block;
        block.vtx.push_back(txNew);
        block.hashPrevBlock = 0;
        block.hashMerkleRoot = block.BuildMerkleTree();
        block.nVersion = 1;
        block.nTime    = 1718524492;
        block.nBits    = 0x1d0fffff;
        block.nNonce   = 0;

        struct unnamed1
        {
            struct unnamed2
            {
                int nVersion;
                uint256 hashPrevBlock;
                uint256 hashMerkleRoot;
                unsigned int nTime;
                unsigned int nBits;
                unsigned int nNonce;
            }
            block;
            unsigned char pchPadding0[64];
            uint256 hash1;
            unsigned char pchPadding1[64];
        }
        tmp;
    
        tmp.block.nVersion       = block.nVersion;
        tmp.block.hashPrevBlock  = block.hashPrevBlock;
        tmp.block.hashMerkleRoot = block.hashMerkleRoot;
        tmp.block.nTime          = block.nTime;
        tmp.block.nBits          = block.nBits ;
        tmp.block.nNonce         = block.nNonce;
    
        unsigned int nBlocks0 = FormatHashBlocks(&tmp.block, sizeof(tmp.block));
        unsigned int nBlocks1 = FormatHashBlocks(&tmp.hash1, sizeof(tmp.hash1));
    
        uint256 hashTarget = CBigNum().SetCompact(block.nBits).getuint256();
        uint256 hash;
    
    loop
    {
        BlockSHA256(&tmp.block, nBlocks0, &tmp.hash1);
        BlockSHA256(&tmp.hash1, nBlocks1, &hash);
    
        if (hash <= hashTarget)
        {
            
            block.nNonce = tmp.block.nNonce;
            assert(hash == block.GetHash());
            printf ("nonce found: %u\n", block.nNonce);
            printf ("hash = %s\n",hash.ToString().c_str());
            printf ("Merkle hash = %s\n",tmp.block.hashMerkleRoot.ToString().c_str());
            break;
        }
        ++tmp.block.nNonce;
    }
}
