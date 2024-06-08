// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2024 Makoto Sakuyama
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

bool RecvLine(SOCKET hSocket, string& strLine);
void ThreadIRCSeed(void* parg);

extern int nGotIRCAddresses;
