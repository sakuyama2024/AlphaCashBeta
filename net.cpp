// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2024 Makoto Sakuyama
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "headers.h"

void ThreadMessageHandler2(void* parg);
void ThreadSocketHandler2(void* parg);
void ThreadOpenConnections2(void* parg);
bool OpenNetworkConnection(const CAddress& addrConnect);





//
// Global state variables
//
bool fClient = false;
uint64 nLocalServices = (fClient ? 0 : NODE_NETWORK);
CAddress addrLocalHost(0, DEFAULT_PORT, nLocalServices);
CNode* pnodeLocalHost = NULL;
uint64 nLocalHostNonce = 0;
std::array<int, 10> vnThreadsRunning;
SOCKET hListenSocket = INVALID_SOCKET;
int64 nThreadSocketHandlerHeartbeat = INT64_MAX;

vector<CNode*> vNodes;
CCriticalSection cs_vNodes;
map<vector<unsigned char>, CAddress> mapAddresses;
CCriticalSection cs_mapAddresses;
map<CInv, CDataStream> mapRelay;
deque<pair<int64, CInv> > vRelayExpiration;
CCriticalSection cs_mapRelay;
map<CInv, int64> mapAlreadyAskedFor;

// Settings
int fUseProxy = false;
CAddress addrProxy("127.0.0.1:9050");





void CNode::PushGetBlocks(CBlockIndex* pindexBegin, uint256 hashEnd)
{
    // Filter out duplicate requests
    if (pindexBegin == pindexLastGetBlocksBegin && hashEnd == hashLastGetBlocksEnd)
        return;
    pindexLastGetBlocksBegin = pindexBegin;
    hashLastGetBlocksEnd = hashEnd;

    PushMessage("getblocks", CBlockLocator(pindexBegin), hashEnd);
}





bool ConnectSocket(const CAddress& addrConnect, SOCKET& hSocketRet)
{
    hSocketRet = INVALID_SOCKET;

    SOCKET hSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (hSocket == INVALID_SOCKET)
        return false;
#if defined(__BSD__) || defined(__WXOSX__)
    int set = 1;
    setsockopt(hSocket, SOL_SOCKET, SO_NOSIGPIPE, (void*)&set, sizeof(int));
#endif

    bool fRoutable = !(addrConnect.GetByte(3) == 10 || (addrConnect.GetByte(3) == 192 && addrConnect.GetByte(2) == 168));
    bool fProxy = (fUseProxy && fRoutable);
    struct sockaddr_in sockaddr = (fProxy ? addrProxy.GetSockAddr() : addrConnect.GetSockAddr());

    if (connect(hSocket, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == SOCKET_ERROR)
    {
        closesocket(hSocket);
        return false;
    }

    if (fProxy)
    {
        printf("proxy connecting %s\n", addrConnect.ToStringLog().c_str());
        char pszSocks4IP[] = "\4\1\0\0\0\0\0\0user";
        memcpy(pszSocks4IP + 2, &addrConnect.port, 2);
        memcpy(pszSocks4IP + 4, &addrConnect.ip, 4);
        char* pszSocks4 = pszSocks4IP;
        int nSize = sizeof(pszSocks4IP);

        int ret = send(hSocket, pszSocks4, nSize, MSG_NOSIGNAL);
        if (ret != nSize)
        {
            closesocket(hSocket);
            return error("Error sending to proxy");
        }
        char pchRet[8];
        if (recv(hSocket, pchRet, 8, 0) != 8)
        {
            closesocket(hSocket);
            return error("Error reading proxy response");
        }
        if (pchRet[1] != 0x5a)
        {
            closesocket(hSocket);
            if (pchRet[1] != 0x5b)
                printf("ERROR: Proxy returned error %d\n", pchRet[1]);
            return false;
        }
        printf("proxy connected %s\n", addrConnect.ToStringLog().c_str());
    }

    hSocketRet = hSocket;
    return true;
}


bool AddAddress(CAddress addr)
{
    if (!addr.IsRoutable())
        return false;
    if (addr.ip == addrLocalHost.ip)
        return false;
    CRITICAL_BLOCK(cs_mapAddresses)
    {
        map<vector<unsigned char>, CAddress>::iterator it = mapAddresses.find(addr.GetKey());
        if (it == mapAddresses.end())
        {
            // New address
            
            std:string s = addr.ToStringIPPort();
            printf("AddAddress(%s)\n", s.c_str());
            mapAddresses.insert(make_pair(addr.GetKey(), addr));
            CAddrDB().WriteAddress(addr);
            return true;
        }
        else
        {
            bool fUpdated = false;
            CAddress& addrFound = (*it).second;
            if ((addrFound.nServices | addr.nServices) != addrFound.nServices)
            {
                // Services have been added
                addrFound.nServices |= addr.nServices;
                fUpdated = true;
            }
            bool fCurrentlyOnline = (GetAdjustedTime() - addr.nTime < 24 * 60 * 60);
            int64 nUpdateInterval = (fCurrentlyOnline ? 60 * 60 : 24 * 60 * 60);
            if (addrFound.nTime < addr.nTime - nUpdateInterval)
            {
                // Periodically update most recently seen time
                addrFound.nTime = addr.nTime;
                fUpdated = true;
            }
            if (fUpdated)
                CAddrDB().WriteAddress(addrFound);
        }
    }
    return false;
}

void AddressCurrentlyConnected(const CAddress& addr)
{
    CRITICAL_BLOCK(cs_mapAddresses)
    {
        // Only if it's been published already
        map<vector<unsigned char>, CAddress>::iterator it = mapAddresses.find(addr.GetKey());
        if (it != mapAddresses.end())
        {
            CAddress& addrFound = (*it).second;
            int64 nUpdateInterval = 20 * 60;
            if (addrFound.nTime < GetAdjustedTime() - nUpdateInterval)
            {
                // Periodically update most recently seen time
                addrFound.nTime = GetAdjustedTime();
                CAddrDB addrdb;
                addrdb.WriteAddress(addrFound);
            }
        }
    }
}





void AbandonRequests(void (*fn)(void*, CDataStream&), void* param1)
{
    // If the dialog might get closed before the reply comes back,
    // call this in the destructor so it doesn't get called after it's deleted.
    CRITICAL_BLOCK(cs_vNodes)
    {
        foreach(CNode* pnode, vNodes)
        {
            CRITICAL_BLOCK(pnode->cs_mapRequests)
            {
                for (map<uint256, CRequestTracker>::iterator mi = pnode->mapRequests.begin(); mi != pnode->mapRequests.end();)
                {
                    CRequestTracker& tracker = (*mi).second;
                    if (tracker.fn == fn && tracker.param1 == param1)
                        pnode->mapRequests.erase(mi++);
                    else
                        mi++;
                }
            }
        }
    }
}







//
// Subscription methods for the broadcast and subscription system.
// Channel numbers are message numbers, i.e. MSG_TABLE and MSG_PRODUCT.
//
// The subscription system uses a meet-in-the-middle strategy.
// With 100,000 nodes, if senders broadcast to 1000 random nodes and receivers
// subscribe to 1000 random nodes, 99.995% (1 - 0.99^1000) of messages will get through.
//

bool AnySubscribed(unsigned int nChannel)
{
    if (pnodeLocalHost->IsSubscribed(nChannel))
        return true;
    CRITICAL_BLOCK(cs_vNodes)
        foreach(CNode* pnode, vNodes)
            if (pnode->IsSubscribed(nChannel))
                return true;
    return false;
}

bool CNode::IsSubscribed(unsigned int nChannel)
{
    if (nChannel >= vfSubscribe.size())
        return false;
    return vfSubscribe[nChannel];
}

void CNode::Subscribe(unsigned int nChannel, unsigned int nHops)
{
    if (nChannel >= vfSubscribe.size())
        return;

    if (!AnySubscribed(nChannel))
    {
        // Relay subscribe
        CRITICAL_BLOCK(cs_vNodes)
            foreach(CNode* pnode, vNodes)
                if (pnode != this)
                    pnode->PushMessage("subscribe", nChannel, nHops);
    }

    vfSubscribe[nChannel] = true;
}

void CNode::CancelSubscribe(unsigned int nChannel)
{
    if (nChannel >= vfSubscribe.size())
        return;

    // Prevent from relaying cancel if wasn't subscribed
    if (!vfSubscribe[nChannel])
        return;
    vfSubscribe[nChannel] = false;

    if (!AnySubscribed(nChannel))
    {
        // Relay subscription cancel
        CRITICAL_BLOCK(cs_vNodes)
            foreach(CNode* pnode, vNodes)
                if (pnode != this)
                    pnode->PushMessage("sub-cancel", nChannel);
    }
}









CNode* FindNode(unsigned int ip)
{
    CRITICAL_BLOCK(cs_vNodes)
    {
        foreach(CNode* pnode, vNodes)
            if (pnode->addr.ip == ip)
                return (pnode);
    }
    return NULL;
}

CNode* FindNode(CAddress addr)
{
    CRITICAL_BLOCK(cs_vNodes)
    {
        foreach(CNode* pnode, vNodes)
            if (pnode->addr == addr)
                return (pnode);
    }
    return NULL;
}

CNode* ConnectNode(CAddress addrConnect, int64 nTimeout)
{
    if (addrConnect.ip == addrLocalHost.ip)
        return NULL;

    // Look for an existing connection
    CNode* pnode = FindNode(addrConnect.ip);
    if (pnode)
    {
        if (nTimeout != 0)
            pnode->AddRef(nTimeout);
        else
            pnode->AddRef();
        return pnode;
    }

    /// debug print
    
    std:string s = addrConnect.ToStringIPPort();
    printf("trying connection %s lastseen=%.1fhrs lasttry=%.1fhrs\n",
        s.c_str(),
        (double)(addrConnect.nTime - GetAdjustedTime())/3600.0,
        (double)(addrConnect.nLastTry - GetAdjustedTime())/3600.0);

    CRITICAL_BLOCK(cs_mapAddresses)
        mapAddresses[addrConnect.GetKey()].nLastTry = GetAdjustedTime();

    // Connect
    SOCKET hSocket;
    if (ConnectSocket(addrConnect, hSocket))
    {
        /// debug print
        printf("connected %s\n", addrConnect.ToStringLog().c_str());

        // Set to nonblocking
#ifdef __WXMSW__
        u_long nOne = 1;
        if (ioctlsocket(hSocket, FIONBIO, &nOne) == SOCKET_ERROR)
            printf("ConnectSocket() : ioctlsocket nonblocking setting failed, error %d\n", WSAGetLastError());
#else
        if (fcntl(hSocket, F_SETFL, O_NONBLOCK) == SOCKET_ERROR)
            printf("ConnectSocket() : fcntl nonblocking setting failed, error %d\n", errno);
#endif

        // Add node
        CNode* pnode = new CNode(hSocket, addrConnect, false);
        if (nTimeout != 0)
            pnode->AddRef(nTimeout);
        else
            pnode->AddRef();
        CRITICAL_BLOCK(cs_vNodes)
            vNodes.push_back(pnode);

        pnode->nTimeConnected = GetTime();
        return pnode;
    }
    else
    {
        return NULL;
    }
}

void CNode::CloseSocketDisconnect()
{
    fDisconnect = true;
    if (hSocket != INVALID_SOCKET)
    {
        if (fDebug)
            printf("%s ", DateTimeStrFormat("%x %H:%M:%S", GetTime()).c_str());
        printf("disconnecting node %s\n", addr.ToStringLog().c_str());
        closesocket(hSocket);
        hSocket = INVALID_SOCKET;
    }
}

void CNode::Cleanup()
{
    // All of a nodes broadcasts and subscriptions are automatically torn down
    // when it goes down, so a node has to stay up to keep its broadcast going.

    // Cancel subscriptions
    for (unsigned int nChannel = 0; nChannel < vfSubscribe.size(); nChannel++)
        if (vfSubscribe[nChannel])
            CancelSubscribe(nChannel);
}


void ThreadSocketHandler(void* parg)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadSocketHandler(parg));
    try
    {
        vnThreadsRunning[0]++;
        ThreadSocketHandler2(parg);
        vnThreadsRunning[0]--;
    }
    catch (std::exception& e) {
        vnThreadsRunning[0]--;
        PrintException(&e, "ThreadSocketHandler()");
    } catch (...) {
        vnThreadsRunning[0]--;
        throw; // support pthread_cancel()
    }
    printf("ThreadSocketHandler exiting\n");
}

void ThreadSocketHandler2(void* parg)
{
    printf("ThreadSocketHandler started\n");
    list<CNode*> vNodesDisconnected;
    int nPrevNodeCount = 0;

    loop
    {
        //
        // Disconnect nodes
        //
        CRITICAL_BLOCK(cs_vNodes)
        {
            // Disconnect unused nodes
            vector<CNode*> vNodesCopy = vNodes;
            foreach(CNode* pnode, vNodesCopy)
            {
                if (pnode->fDisconnect ||
                    (pnode->GetRefCount() <= 0 && pnode->vRecv.empty() && pnode->vSend.empty()))
                {
                    // remove from vNodes
                    vNodes.erase(remove(vNodes.begin(), vNodes.end(), pnode), vNodes.end());

                    // close socket and cleanup
                    pnode->CloseSocketDisconnect();
                    pnode->Cleanup();

                    // hold in disconnected pool until all refs are released
                    pnode->nReleaseTime = max(pnode->nReleaseTime, GetTime() + 15 * 60);
                    if (pnode->fNetworkNode || pnode->fInbound)
                        pnode->Release();
                    vNodesDisconnected.push_back(pnode);
                }
            }

            // Delete disconnected nodes
            list<CNode*> vNodesDisconnectedCopy = vNodesDisconnected;
            foreach(CNode* pnode, vNodesDisconnectedCopy)
            {
                // wait until threads are done using it
                if (pnode->GetRefCount() <= 0)
                {
                    bool fDelete = false;
                    TRY_CRITICAL_BLOCK(pnode->cs_vSend)
                     TRY_CRITICAL_BLOCK(pnode->cs_vRecv)
                      TRY_CRITICAL_BLOCK(pnode->cs_mapRequests)
                       TRY_CRITICAL_BLOCK(pnode->cs_inventory)
                        fDelete = true;
                    if (fDelete)
                    {
                        vNodesDisconnected.remove(pnode);
                        delete pnode;
                    }
                }
            }
        }
        if (vNodes.size() != nPrevNodeCount)
        {
            nPrevNodeCount = vNodes.size();
            MainFrameRepaint();
        }


        //
        // Find which sockets have data to receive
        //
        struct timeval timeout;
        timeout.tv_sec  = 0;
        timeout.tv_usec = 50000; // frequency to poll pnode->vSend

        fd_set fdsetRecv;
        fd_set fdsetSend;
        fd_set fdsetError;
        FD_ZERO(&fdsetRecv);
        FD_ZERO(&fdsetSend);
        FD_ZERO(&fdsetError);
        SOCKET hSocketMax = 0;
        FD_SET(hListenSocket, &fdsetRecv);
        hSocketMax = max(hSocketMax, hListenSocket);
        CRITICAL_BLOCK(cs_vNodes)
        {
            foreach(CNode* pnode, vNodes)
            {
                if (pnode->hSocket == INVALID_SOCKET || pnode->hSocket < 0)
                    continue;
                FD_SET(pnode->hSocket, &fdsetRecv);
                FD_SET(pnode->hSocket, &fdsetError);
                hSocketMax = max(hSocketMax, pnode->hSocket);
                TRY_CRITICAL_BLOCK(pnode->cs_vSend)
                    if (!pnode->vSend.empty())
                        FD_SET(pnode->hSocket, &fdsetSend);
            }
        }

        vnThreadsRunning[0]--;
        int nSelect = select(hSocketMax + 1, &fdsetRecv, &fdsetSend, &fdsetError, &timeout);
        vnThreadsRunning[0]++;
        if (fShutdown)
            return;
        if (nSelect == SOCKET_ERROR)
        {
            int nErr = WSAGetLastError();
            printf("socket select error %d\n", nErr);
            for (int i = 0; i <= hSocketMax; i++)
                FD_SET(i, &fdsetRecv);
            FD_ZERO(&fdsetSend);
            FD_ZERO(&fdsetError);
            Sleep(timeout.tv_usec/1000);
        }


        //
        // Accept new connections
        //
        if (FD_ISSET(hListenSocket, &fdsetRecv))
        {
            struct sockaddr_in sockaddr;
            socklen_t len = sizeof(sockaddr);
            SOCKET hSocket = accept(hListenSocket, (struct sockaddr*)&sockaddr, &len);
            CAddress addr(sockaddr);
            if (hSocket == INVALID_SOCKET)
            {
                if (WSAGetLastError() != WSAEWOULDBLOCK)
                    printf("socket error accept failed: %d\n", WSAGetLastError());
            }
            else
            {
                printf("accepted connection %s\n", addr.ToStringLog().c_str());
                CNode* pnode = new CNode(hSocket, addr, true);
                pnode->AddRef();
                CRITICAL_BLOCK(cs_vNodes)
                    vNodes.push_back(pnode);
            }
        }


        //
        // Service each socket
        //
        vector<CNode*> vNodesCopy;
        CRITICAL_BLOCK(cs_vNodes)
        {
            vNodesCopy = vNodes;
            foreach(CNode* pnode, vNodesCopy)
                pnode->AddRef();
        }
        foreach(CNode* pnode, vNodesCopy)
        {
            if (fShutdown)
                return;

            //
            // Receive
            //
            if (pnode->hSocket == INVALID_SOCKET)
                continue;
            if (FD_ISSET(pnode->hSocket, &fdsetRecv) || FD_ISSET(pnode->hSocket, &fdsetError))
            {
                TRY_CRITICAL_BLOCK(pnode->cs_vRecv)
                {
                    CDataStream& vRecv = pnode->vRecv;
                    unsigned int nPos = vRecv.size();

                    // typical socket buffer is 8K-64K
                    char pchBuf[0x10000];
                    int nBytes = recv(pnode->hSocket, pchBuf, sizeof(pchBuf), MSG_DONTWAIT);
                    if (nBytes > 0)
                    {
                        vRecv.resize(nPos + nBytes);
                        memcpy(&vRecv[nPos], pchBuf, nBytes);
                        pnode->nLastRecv = GetTime();
                    }
                    else if (nBytes == 0)
                    {
                        // socket closed gracefully
                        if (!pnode->fDisconnect)
                            printf("socket closed\n");
                        pnode->CloseSocketDisconnect();
                    }
                    else if (nBytes < 0)
                    {
                        // error
                        int nErr = WSAGetLastError();
                        if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE && nErr != WSAEINTR && nErr != WSAEINPROGRESS)
                        {
                            if (!pnode->fDisconnect)
                                printf("socket recv error %d\n", nErr);
                            pnode->CloseSocketDisconnect();
                        }
                    }
                }
            }

            //
            // Send
            //
            if (pnode->hSocket == INVALID_SOCKET)
                continue;
            if (FD_ISSET(pnode->hSocket, &fdsetSend))
            {
                TRY_CRITICAL_BLOCK(pnode->cs_vSend)
                {
                    CDataStream& vSend = pnode->vSend;
                    if (!vSend.empty())
                    {
                        int nBytes = send(pnode->hSocket, &vSend[0], vSend.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
                        if (nBytes > 0)
                        {
                            vSend.erase(vSend.begin(), vSend.begin() + nBytes);
                            pnode->nLastSend = GetTime();
                        }
                        else if (nBytes < 0)
                        {
                            // error
                            int nErr = WSAGetLastError();
                            if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE && nErr != WSAEINTR && nErr != WSAEINPROGRESS)
                            {
                                printf("socket send error %d\n", nErr);
                                pnode->CloseSocketDisconnect();
                            }
                        }
                    }
                }
            }

            //
            // Inactivity checking
            //
            if (pnode->vSend.empty())
                pnode->nLastSendEmpty = GetTime();
            if (GetTime() - pnode->nTimeConnected > 60)
            {
                if (pnode->nLastRecv == 0 || pnode->nLastSend == 0)
                {
                    printf("socket no message in first 60 seconds, %d %d\n", pnode->nLastRecv != 0, pnode->nLastSend != 0);
                    pnode->fDisconnect = true;
                }
                else if (GetTime() - pnode->nLastSend > 90*60 && GetTime() - pnode->nLastSendEmpty > 90*60)
                {
                    printf("socket not sending\n");
                    pnode->fDisconnect = true;
                }
                else if (GetTime() - pnode->nLastRecv > 90*60)
                {
                    printf("socket inactivity timeout\n");
                    pnode->fDisconnect = true;
                }
            }
        }
        CRITICAL_BLOCK(cs_vNodes)
        {
            foreach(CNode* pnode, vNodesCopy)
                pnode->Release();
        }

        nThreadSocketHandlerHeartbeat = GetTime();
        Sleep(10);
    }
}


unsigned int pnSeed[] =
{
    0x6e2d52c3,0x9e8d3f5c,0x9d0ffbcd
};

// Function to convert hex seed to string IP
std::string ConvertSeedToIP(unsigned int seed) {
    unsigned char bytes[4];
    bytes[0] = seed & 0xFF;
    bytes[1] = (seed >> 8) & 0xFF;
    bytes[2] = (seed >> 16) & 0xFF;
    bytes[3] = (seed >> 24) & 0xFF;
    std::ostringstream ip;
    ip << static_cast<int>(bytes[3]) << "."
       << static_cast<int>(bytes[2]) << "."
       << static_cast<int>(bytes[1]) << "."
       << static_cast<int>(bytes[0]);
    return ip.str();
}

// Function to get the list of seed nodes
std::vector<std::string> GetSeedNodes() {
    std::vector<std::string> seeds;
    for (unsigned int seed : pnSeed) {
        seeds.push_back(ConvertSeedToIP(seed));
    }
    return seeds;
}

// Function to check if an address is a seed node
bool IsSeedNode(const std::string& ip) {
    std::vector<std::string> seeds = GetSeedNodes();
    return std::find(seeds.begin(), seeds.end(), ip) != seeds.end();
}


void ThreadOpenConnections(void* parg)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadOpenConnections(parg));
    try
    {
        vnThreadsRunning[1]++;
        ThreadOpenConnections2(parg);
        vnThreadsRunning[1]--;
    }
    catch (std::exception& e) {
        vnThreadsRunning[1]--;
        PrintException(&e, "ThreadOpenConnections()");
    } catch (...) {
        vnThreadsRunning[1]--;
        PrintException(NULL, "ThreadOpenConnections()");
    }
    printf("ThreadOpenConnections exiting\n");
}

void ThreadOpenConnections2(void* parg)
{
    printf("ThreadOpenConnections started\n");

    // Connect to specific addresses
    if (mapArgs.count("-connect"))
    {
        for (int64 nLoop = 0;; nLoop++)
        {
            foreach(string strAddr, mapMultiArgs["-connect"])
            {
                CAddress addr(strAddr, NODE_NETWORK);
                if (addr.IsValid())
                    OpenNetworkConnection(addr);
                for (int i = 0; i < 10 && i < nLoop; i++)
                {
                    Sleep(500);
                    if (fShutdown)
                        return;
                }
            }
        }
    }

    // Connect to manually added nodes first
    if (mapArgs.count("-addnode"))
    {
        foreach(string strAddr, mapMultiArgs["-addnode"])
        {
            CAddress addr(strAddr, NODE_NETWORK);
            if (addr.IsValid())
            {
                OpenNetworkConnection(addr);
                Sleep(500);
                if (fShutdown)
                    return;
            }
        }
    }

    // Initiate network connections
    int64 nStart = GetTime();
    loop
    {
        // Wait
        vnThreadsRunning[1]--;
        Sleep(500);
        const int nMaxConnections = 8;
        while (vNodes.size() >= nMaxConnections)
        {
            Sleep(2000);
            if (fShutdown)
                return;
        }
        vnThreadsRunning[1]++;
        if (fShutdown)
            return;

        CRITICAL_BLOCK(cs_mapAddresses)
        {
            // Add seed nodes if IRC isn't working
            static bool fSeedUsed;
            bool fTOR = (fUseProxy && addrProxy.port == htons(9050));
//            if (mapAddresses.empty() && (GetTime() - nStart > 60 || fTOR))
            if (mapAddresses.empty() && (GetTime() - nStart > 0 || fTOR))
            {
                
                printf("number of Seeds: %i \n",ARRAYLEN(pnSeed));
                for (int i = 0; i < ARRAYLEN(pnSeed); i++)
                {
                    // It'll only connect to one or two seed nodes because once it connects,
                    // it'll get a pile of addresses with newer timestamps.
                    CAddress addr;
                    addr.ip = pnSeed[i];
                    addr.nTime = 0;
                    
                    std::string s = addr.ToStringIPPort();
                    printf("adding seed %s\n",s.c_str());
                    
                    AddAddress(addr);
                }
                fSeedUsed = true;
            }
        }


        //
        // Choose an address to connect to based on most recently seen
        //
        CAddress addrConnect;
        int64 nBest = INT64_MIN;

        // Do this here so we don't have to critsect vNodes inside mapAddresses critsect
        set<unsigned int> setConnected;
        CRITICAL_BLOCK(cs_vNodes)
            foreach(CNode* pnode, vNodes)
                setConnected.insert(pnode->addr.ip);

        CRITICAL_BLOCK(cs_mapAddresses)
        {
            foreach(const PAIRTYPE(vector<unsigned char>, CAddress)& item, mapAddresses)
            {
                const CAddress& addr = item.second;
                if (!addr.IsIPv4() || !addr.IsValid() || setConnected.count(addr.ip))
                    continue;
                int64 nSinceLastSeen = GetAdjustedTime() - addr.nTime;
                int64 nSinceLastTry = GetAdjustedTime() - addr.nLastTry;

                // Randomize the order in a deterministic way, putting the standard port first
                int64 nRandomizer = (uint64)(nStart * 4951 + addr.nLastTry * 9567851 + addr.ip * 7789) % (2 * 60 * 60);
                if (addr.port != DEFAULT_PORT)
                    nRandomizer += 2 * 60 * 60;

                // Last seen  Base retry frequency
                //   <1 hour   10 min
                //    1 hour    1 hour
                //    4 hours   2 hours
                //   24 hours   5 hours
                //   48 hours   7 hours
                //    7 days   13 hours
                //   30 days   27 hours
                //   90 days   46 hours
                //  365 days   93 hours
                int64 nDelay = (int64)(3600.0 * sqrt(fabs((double)nSinceLastSeen) / 3600.0) + nRandomizer);

                // Fast reconnect for one hour after last seen
                if (nSinceLastSeen < 60 * 60)
                    nDelay = 10 * 60;

                // Limit retry frequency
                if (nSinceLastTry < nDelay)
                    continue;

                // Only try the old stuff if we don't have enough connections
                if (vNodes.size() >= 8 && nSinceLastSeen > 24 * 60 * 60)
                    continue;

                // If multiple addresses are ready, prioritize by time since
                // last seen and time since last tried.
                int64 nScore = min(nSinceLastTry, (int64)24 * 60 * 60) - nSinceLastSeen - nRandomizer;
                if (nScore > nBest)
                {
                    nBest = nScore;
                    addrConnect = addr;
                }
            }
        }

        if (addrConnect.IsValid())
            OpenNetworkConnection(addrConnect);
    }
}

bool OpenNetworkConnection(const CAddress& addrConnect)
{
    //
    // Initiate outbound network connection
    //
    if (fShutdown)
        return false;
    if (addrConnect.ip == addrLocalHost.ip || !addrConnect.IsIPv4() || FindNode(addrConnect.ip))
        return false;

    vnThreadsRunning[1]--;
    CNode* pnode = ConnectNode(addrConnect);
    vnThreadsRunning[1]++;
    if (fShutdown)
        return false;
    if (!pnode)
        return false;
    pnode->fNetworkNode = true;

    if (addrLocalHost.IsRoutable() && !fUseProxy)
    {
        // Advertise our address
        vector<CAddress> vAddr;
        vAddr.push_back(addrLocalHost);
        pnode->PushMessage("addr", vAddr);
    }

    // Get as many addresses as we can
    pnode->PushMessage("getaddr");
    pnode->fGetAddr = true; // don't relay the results of the getaddr

    ////// should the one on the receiving end do this too?
    // Subscribe our local subscription list
    const unsigned int nHops = 0;
    for (unsigned int nChannel = 0; nChannel < pnodeLocalHost->vfSubscribe.size(); nChannel++)
        if (pnodeLocalHost->vfSubscribe[nChannel])
            pnode->PushMessage("subscribe", nChannel, nHops);

    return true;
}








void ThreadMessageHandler(void* parg)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadMessageHandler(parg));
    try
    {
        vnThreadsRunning[2]++;
        ThreadMessageHandler2(parg);
        vnThreadsRunning[2]--;
    }
    catch (std::exception& e) {
        vnThreadsRunning[2]--;
        PrintException(&e, "ThreadMessageHandler()");
    } catch (...) {
        vnThreadsRunning[2]--;
        PrintException(NULL, "ThreadMessageHandler()");
    }
    printf("ThreadMessageHandler exiting\n");
}

void ThreadMessageHandler2(void* parg)
{
    printf("ThreadMessageHandler started\n");
    SetThreadPriority(THREAD_PRIORITY_BELOW_NORMAL);
    while (!fShutdown)
    {
        vector<CNode*> vNodesCopy;
        CRITICAL_BLOCK(cs_vNodes)
        {
            vNodesCopy = vNodes;
            foreach(CNode* pnode, vNodesCopy)
                pnode->AddRef();
        }

        // Poll the connected nodes for messages
        CNode* pnodeTrickle = NULL;
        if (!vNodesCopy.empty())
            pnodeTrickle = vNodesCopy[GetRand(vNodesCopy.size())];
        foreach(CNode* pnode, vNodesCopy)
        {
            // Receive messages
            TRY_CRITICAL_BLOCK(pnode->cs_vRecv)
                ProcessMessages(pnode);
            if (fShutdown)
                return;

            // Send messages
            TRY_CRITICAL_BLOCK(pnode->cs_vSend)
                SendMessages(pnode, pnode == pnodeTrickle);
            if (fShutdown)
                return;
        }

        CRITICAL_BLOCK(cs_vNodes)
        {
            foreach(CNode* pnode, vNodesCopy)
                pnode->Release();
        }

        // Wait and allow messages to bunch up
        vnThreadsRunning[2]--;
        Sleep(100);
        vnThreadsRunning[2]++;
        if (fShutdown)
            return;
    }
}









bool BindListenPort(string& strError)
{
    strError = "";
    int nOne = 1;

#ifdef __WXMSW__
    // Initialize Windows Sockets
    WSADATA wsadata;
    int ret = WSAStartup(MAKEWORD(2,2), &wsadata);
    if (ret != NO_ERROR)
    {
        strError = strprintf("Error: TCP/IP socket library failed to start (WSAStartup returned error %d)", ret);
        printf("%s\n", strError.c_str());
        return false;
    }
#endif

    // Create socket for listening for incoming connections
    hListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (hListenSocket == INVALID_SOCKET)
    {
        strError = strprintf("Error: Couldn't open socket for incoming connections (socket returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }

#if defined(__BSD__) || defined(__WXOSX__)
    // Different way of disabling SIGPIPE on BSD
    setsockopt(hListenSocket, SOL_SOCKET, SO_NOSIGPIPE, (void*)&nOne, sizeof(int));
#endif

#ifndef __WXMSW__
    // Allow binding if the port is still in TIME_WAIT state after
    // the program was closed and restarted.  Not an issue on windows.
    setsockopt(hListenSocket, SOL_SOCKET, SO_REUSEADDR, (void*)&nOne, sizeof(int));
#endif

#ifdef __WXMSW__
    // Set to nonblocking, incoming connections will also inherit this
    if (ioctlsocket(hListenSocket, FIONBIO, (u_long*)&nOne) == SOCKET_ERROR)
#else
    if (fcntl(hListenSocket, F_SETFL, O_NONBLOCK) == SOCKET_ERROR)
#endif
    {
        strError = strprintf("Error: Couldn't set properties on socket for incoming connections (error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }

    // The sockaddr_in structure specifies the address family,
    // IP address, and port for the socket that is being bound
    struct sockaddr_in sockaddr;
    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_addr.s_addr = INADDR_ANY; // bind to all IPs on this computer
    sockaddr.sin_port = DEFAULT_PORT;
    if (::bind(hListenSocket, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == SOCKET_ERROR)
    {
        int nErr = WSAGetLastError();
        if (nErr == WSAEADDRINUSE)
            strError = strprintf("Unable to bind to port %d on this computer.  Alphacash is probably already running.", ntohs(sockaddr.sin_port));
        else
            strError = strprintf("Error: Unable to bind to port %d on this computer (bind returned error %d)", ntohs(sockaddr.sin_port), nErr);
        printf("%s\n", strError.c_str());
        return false;
    }
    printf("Bound to port %d\n", ntohs(sockaddr.sin_port));

    // Listen for incoming connections
    if (listen(hListenSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        strError = strprintf("Error: Listening for incoming connections failed (listen returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }

    return true;
}

void StartNode(void* parg)
{
    if (pnodeLocalHost == NULL)
        pnodeLocalHost = new CNode(INVALID_SOCKET, CAddress("127.0.0.1", nLocalServices));

#ifdef __WXMSW__
    // Get local host ip
    char pszHostName[1000] = "";
    if (gethostname(pszHostName, sizeof(pszHostName)) != SOCKET_ERROR)
    {
        struct hostent* phostent = gethostbyname(pszHostName);
        if (phostent)
        {
            // Take the first IP that isn't loopback 127.x.x.x
            for (int i = 0; phostent->h_addr_list[i] != NULL; i++)
                printf("host ip %d: %s\n", i, CAddress(*(unsigned int*)phostent->h_addr_list[i]).ToStringIP().c_str());
            for (int i = 0; phostent->h_addr_list[i] != NULL; i++)
            {
                CAddress addr(*(unsigned int*)phostent->h_addr_list[i], DEFAULT_PORT, nLocalServices);
                if (addr.IsValid() && addr.GetByte(3) != 127)
                {
                    addrLocalHost = addr;
                    break;
                }
            }
        }
    }
#else
    // Get local host ip
    struct ifaddrs* myaddrs;
    if (getifaddrs(&myaddrs) == 0)
    {
        for (struct ifaddrs* ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next)
        {
            if (ifa->ifa_addr == NULL) continue;
            if ((ifa->ifa_flags & IFF_UP) == 0) continue;
            if (strcmp(ifa->ifa_name, "lo") == 0) continue;
            if (strcmp(ifa->ifa_name, "lo0") == 0) continue;
            char pszIP[100];
            if (ifa->ifa_addr->sa_family == AF_INET)
            {
                struct sockaddr_in* s4 = (struct sockaddr_in*)(ifa->ifa_addr);
                if (inet_ntop(ifa->ifa_addr->sa_family, (void*)&(s4->sin_addr), pszIP, sizeof(pszIP)) != NULL)
                    printf("ipv4 %s: %s\n", ifa->ifa_name, pszIP);

                // Take the first IP that isn't loopback 127.x.x.x
                CAddress addr(*(unsigned int*)&s4->sin_addr, DEFAULT_PORT, nLocalServices);
                if (addr.IsValid() && addr.GetByte(3) != 127)
                {
                    addrLocalHost = addr;
                    break;
                }
            }
            else if (ifa->ifa_addr->sa_family == AF_INET6)
            {
                struct sockaddr_in6* s6 = (struct sockaddr_in6*)(ifa->ifa_addr);
                if (inet_ntop(ifa->ifa_addr->sa_family, (void*)&(s6->sin6_addr), pszIP, sizeof(pszIP)) != NULL)
                    printf("ipv6 %s: %s\n", ifa->ifa_name, pszIP);
            }
        }
        freeifaddrs(myaddrs);
    }
#endif
    printf("addrLocalHost = %s\n", addrLocalHost.ToString().c_str());

    // Get our external IP address for incoming connections
    if (fUseProxy)
    {
        // Proxies can't take incoming connections
        addrLocalHost.ip = CAddress("0.0.0.0").ip;
        printf("addrLocalHost = %s\n", addrLocalHost.ToString().c_str());
    }
    else
    {
        if (addrIncoming.IsValid())
            addrLocalHost.ip = addrIncoming.ip;
    }

    //
    // Start threads
    //


    // Send and receive from sockets, accept connections
    pthread_t hThreadSocketHandler = CreateThread(ThreadSocketHandler, NULL, true);

    // Initiate outbound connections
    if (!CreateThread(ThreadOpenConnections, NULL))
        printf("Error: CreateThread(ThreadOpenConnections) failed\n");

    // Process messages
    if (!CreateThread(ThreadMessageHandler, NULL))
        printf("Error: CreateThread(ThreadMessageHandler) failed\n");

    // Generate coins in the background
    GenerateAlphas(fGenerateAlphas);

    //
    // Thread monitoring
    // Not really needed anymore, the cause of the hanging was fixed
    //
}

bool StopNode()
{
    printf("StopNode()\n");
    fShutdown = true;
    nTransactionsUpdated++;
    int64 nStart = GetTime();
    while (vnThreadsRunning[0] > 0 || vnThreadsRunning[2] > 0 || vnThreadsRunning[3] > 0 || vnThreadsRunning[4] > 0)
    {
        if (GetTime() - nStart > 20)
            break;
        Sleep(20);
    }
    if (vnThreadsRunning[0] > 0) printf("ThreadSocketHandler still running\n");
    if (vnThreadsRunning[1] > 0) printf("ThreadOpenConnections still running\n");
    if (vnThreadsRunning[2] > 0) printf("ThreadMessageHandler still running\n");
    if (vnThreadsRunning[3] > 0) printf("ThreadAlphacashMiner still running\n");
    if (vnThreadsRunning[4] > 0) printf("ThreadRPCServer still running\n");
    while (vnThreadsRunning[2] > 0 || vnThreadsRunning[4] > 0)
        Sleep(20);
    Sleep(50);

    return true;
}

class CNetCleanup
{
public:
    CNetCleanup()
    {
    }
    ~CNetCleanup()
    {
        // Close sockets
        foreach(CNode* pnode, vNodes)
            if (pnode->hSocket != INVALID_SOCKET)
                closesocket(pnode->hSocket);
        if (hListenSocket != INVALID_SOCKET)
            if (closesocket(hListenSocket) == SOCKET_ERROR)
                printf("closesocket(hListenSocket) failed with error %d\n", WSAGetLastError());

#ifdef __WXMSW__
        // Shutdown Windows Sockets
        WSACleanup();
#endif
    }
}
instance_of_cnetcleanup;
