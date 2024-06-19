// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2024 Makoto Sakuyama
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef ALPHAUTIL_H
#define ALPHAUTIL_H

std::string formatTimestamp(uint32_t timestamp);
int FormatHashBlocks(void* pbuffer, unsigned int len);
void RegenerateGenesisBlock();
void BlockSHA256(const void* pin, unsigned int nBlocks, void* pout);

#endif ALPHAUTIL_H
