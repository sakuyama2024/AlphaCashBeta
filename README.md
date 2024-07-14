Abstract: Alphacash is a censorship resistant peer-to-peer electronic cash system. Similar to Bitcoin, it uses a fixed emission schedule and longest chain Proof of Work consensus protocol. Unlike Bitcoin, it supports unlimited blocksize with a multi-machine horizontally scaling architecture, without sacrificing security or censorship resistance. The Alphacash coins replicate the self-verifiability property of physical cash, i.e. the coins are compact, authenticated data structures which can be passed through any medium peer-to-peer, chain-to-chain and verified without bridges or trusted third parties. Alphacash completes the Bitcoin vision, functioning as an Internet currency, a medium of exchange and a genuine alternative to physical cash.


The initial code is a minimalist version of Bitcoin PoW forked from 0.3 

The key change is in the transaction validation code - transactions are only valid if they have single input. 

                size_t no_of_inputs = vin.size();
                if (no_of_inputs > 1)
                    return false;

Other changes

block time is targeted at 2 mins, with 10 coins paid per block. Difficulty adjustment occurs every 2 weeks/5. Initially dificulty is set to 1d0fffff which equals approx 2 minutes per block on the seen nodes running a single cpu miner Eventually others will come and the difficulty will rise but no point wasting energy until then.
Coinbase maturity 120 blocks

Genesis Block "Financial Times 25/May/2024 What went wrong with capitalism"


Original integer overflow bug has been fixed
Script Interpreter has been removed - supports only P2PK and P2PKH
Coinbase scripts restricted to 75 bytes or less
DNS Seeding removed - currently 3 seed nodes hardwired
IRC removed 

Dependencies: boost, openssl, cryptopp, berkeley-db, wxWidgets

Next steps:


Build Go client using BTCD
Plug in bill-based state tree to allow horizontal scaling i.e. the UTXO set can be "decomposed" and distributed amongst many machines operating in parallel.
Implement RandomX ASIC resistant hash function







