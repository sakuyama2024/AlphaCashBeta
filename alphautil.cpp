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
#include "sha256.h"
#include <cstring>
#include <bit>
#include <cstdint>



#include <array>
#include <cstddef>
#include <arm_acle.h>
#include <arm_neon.h>


using CryptoPP::ByteReverse;
static int detectlittleendian = 1;

namespace sha256_arm_shani
{
    void Transform(uint32_t* s, const unsigned char* chunk, size_t blocks);
}

namespace sha256
{
    void Initialize(uint32_t* s);
    void Transform(uint32_t* s, const unsigned char* chunk, size_t blocks);
}




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

void BlockSHA256_ARM(const void* pin, int nBlocks, void* pout) {
    
    uint32_t*  pinput = (uint32_t*)pin;
    uint32_t*  pstate = (uint32_t*)pout;
    
    // Initialize states
    sha256::Initialize(pstate);
    
    for (int n = 0; n < nBlocks; n++)
    {
        sha256_arm_shani::Transform(pstate, reinterpret_cast<const unsigned char*>(pinput + n * 16), 1);
    }
    
    for (int i = 0; i < 8; i++)
        pstate[i] = std::byteswap(pstate[i]);

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
        uint256 hash2;
    
        auto b = tmp;
    

    
    auto start = std::chrono::high_resolution_clock::now();
    loop
    {
        
#if defined(__APPLE__) && defined(ENABLE_ARM_SHANI)
        
        BlockSHA256(&tmp.block, nBlocks0, &tmp.hash1);
        BlockSHA256(&tmp.hash1, nBlocks1, &hash);
#else
        BlockSHA256(&tmp.block, nBlocks0, &tmp.hash1);
        BlockSHA256(&tmp.hash1, nBlocks1, &hash);
#endif
        
//        printf("BLOCKSHA ARM = %s\n",hash2.ToString().c_str());
//        printf("BLOCKSHA     = %s\n",hash.ToString().c_str());

//        assert (hash2 == hash);

        if (hash <= hashTarget)
        {
            
            block.nNonce = tmp.block.nNonce;
            assert(hash == block.GetHash());
            printf ("nonce found: %u\n", block.nNonce);
            printf ("hash = %s\n",hash.ToString().c_str());
            printf ("Merkle hash = %s\n",tmp.block.hashMerkleRoot.ToString().c_str());
            
            auto end = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double> duration = end - start;
     //       printf ("time taken in seconds = %d\n", duration);
            std::cout << "time taken in seconds = " << duration.count() << " seconds\n";
            
            
            break;
        }
        ++tmp.block.nNonce;
    }
}


void GetDifficultyAlpha()
{
    if (pindexBest != NULL)
        
    {
        
        CBigNum bn1 = bnProofOfWorkLimit;
        
        //        bn1.SetCompact(bnProofOfWorkLimit.GetCompact());
        
        printf("Proof of Work limit = %s\n",bn1.getuint256().ToString().c_str());
        
        CBigNum bn2 = bnProofOfWorkLimit;
        uint256 u2 = bn2.getuint256();
        printf ("Pow limit  = %s\n",u2.GetHex().c_str());
        
        
        
        CBigNum bn3  = CBigNum().SetCompact(pindexBest->nBits);
        uint256 u1 = bn3.getuint256();
        printf ("current nbits = %s\n",u1.GetHex().c_str());
        
        
        unsigned int iLimit = bn1.GetCompact();
        printf("Proof of Work limit Compact = %i\n",iLimit);
        
        unsigned int iCurrent = bn3.GetCompact();
        printf("Proof of Work Current = %i\n",iCurrent);
        
    
        
    
        int nShift = 256 - 32 - 31; // to fit in a uint
        

        double dMinimum = (CBigNum().SetCompact(bnProofOfWorkLimit.GetCompact()) >> nShift).getuint();
        double dCurrently = (CBigNum().SetCompact(pindexBest->nBits) >> nShift).getuint();
        double answer = dMinimum / dCurrently;
        int j=0;
    }
}





/*
void checkmacros() {
    #if defined(__APPLE__)
        std::cout << "__APPLE__ is defined" << std::endl;
    #else
        std::cout << "__APPLE__ is not defined" << std::endl;
    #endif

    #if defined(__MACH__)
        std::cout << "__MACH__ is defined" << std::endl;
    #else
        std::cout << "__MACH__ is not defined" << std::endl;
    #endif

    #if defined(__arm64__)
        std::cout << "__arm64__ is defined" << std::endl;
    #else
        std::cout << "__arm64__ is not defined" << std::endl;
    #endif

    #if defined(__aarch64__)
        std::cout << "__aarch64__ is defined" << std::endl;
    #else
        std::cout << "__aarch64__ is not defined" << std::endl;
    #endif

    #include <TargetConditionals.h>
    
    #if defined(TARGET_OS_MAC)
        std::cout << "TARGET_OS_MAC is defined" << std::endl;
    #else
        std::cout << "TARGET_OS_MAC is not defined" << std::endl;
    #endif

    #if defined(TARGET_CPU_ARM64)
        std::cout << "TARGET_CPU_ARM64 is defined" << std::endl;
    #else
        std::cout << "TARGET_CPU_ARM64 is not defined" << std::endl;
    #endif

    #if defined(TARGET_CPU_X86_64)
        std::cout << "TARGET_CPU_X86_64 is defined" << std::endl;
    #else
        std::cout << "TARGET_CPU_X86_64 is not defined" << std::endl;
    #endif
    
    #if defined(TARGET_CPU_X86_64)
        std::cout << "TARGET_CPU_X86_64 is defined" << std::endl;
    #else
        std::cout << "TARGET_CPU_X86_64 is not defined" << std::endl;
    #endif
}


 
 void ComputeHashWithCryptoPP(const unsigned char* data, size_t length, unsigned char* hash) {
     CryptoPP::SHA256 sha256;
     sha256.Update(data, length);
     sha256.Final(hash);
 }
 
 
 void ComputeSHA256Hash(const unsigned char* data, size_t length, unsigned char* hash) {
     CSHA256 sha256;
     sha256.Write(data, length);
     sha256.Finalize(hash);
 }

 void ComputeSHA256Hash(const unsigned char* start, const unsigned char* end, unsigned char* hash) {
     CSHA256 sha256;
     size_t length = end - start;
     sha256.Write(start, length);
     sha256.Finalize(hash);
 }

 
 
 const char* data = "hello world";


 //Calculate the double sha256 using 0.23 hash function
 unsigned char hashX1[CSHA256::OUTPUT_SIZE];
 unsigned char hashX2[CSHA256::OUTPUT_SIZE];

 t =  GetTimeMillis();
 for (int i=0; i< 1; i++)
 {
     ComputeSHA256Hash(reinterpret_cast<const unsigned char*>(data), strlen(data), hashX1);
     ComputeSHA256Hash(reinterpret_cast<const unsigned char*>(hashX1), CSHA256::OUTPUT_SIZE, hashX2);
 }
 t2 =  GetTimeMillis();
 elapsed = t2 - t;

 // Convert unsigned char array to std::vector<unsigned char>
 std::vector<unsigned char> hashVec(hashX2, hashX2 + CSHA256::OUTPUT_SIZE);
 uint256 u2 (hashVec);


 //Calculate the double sha256 using 0.3 hash function
 size_t len = std::strlen(data);
 uint256 result = Hash(data, data + len);

 printf("u2 = %s\n",u2.ToString().c_str());
 printf("result = %s\n",result.ToString().c_str());

 uint256 hash13;
 SHA256((unsigned char*)&data[0],len, (unsigned char*)&hash13);
 uint256 hash14;
 SHA256((unsigned char*)&hash13, sizeof(hash13), (unsigned char*)&hash14);

 
 
 */
