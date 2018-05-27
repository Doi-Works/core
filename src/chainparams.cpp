// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/merkle.h>

#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>

#include <assert.h>

#include <chainparamsseeds.h>


bool CChainParams::IsHistoricBug(const uint256& txid, unsigned nHeight, BugType& type) const
{
    const std::pair<unsigned, uint256> key(nHeight, txid);
    std::map<std::pair<unsigned, uint256>, BugType>::const_iterator mi;

    mi = mapHistoricBugs.find (key);
    if (mi != mapHistoricBugs.end ())
    {
        type = mi->second;
        return true;
    }

    return false;
}

static CBlock CreateGenesisBlock(const CScript& genesisInputScript, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = genesisInputScript;
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "USA überraschen Europa mit einem Gesetz zur Online-Durchsuchung";
    const CScript genesisInputScript = CScript() << 0x1f00ffff << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    const CScript genesisOutputScript = CScript() << ParseHex("042f413ffbe86df73d195832efd61003fe4e7f6c061e75afa06365928fa649dd4a408c4029ca98c9a0bfda2b99e53c587c95d566375036c7f85be51b5a4e150118") << OP_CHECKSIG;
    return CreateGenesisBlock(genesisInputScript, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Build genesis block for testnet.  In doichain, it has a changed timestamp
 * and output script (it uses Bitcoin's).
 */
static CBlock CreateTestnetGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Mark Zuckerberg und Apple-Chef Tim Cook gehen aufeinander los";
    const CScript genesisInputScript = CScript() << 0x1d00ffff << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    const CScript genesisOutputScript = CScript() << ParseHex("042f413ffbe86df73d195832efd61003fe4e7f6c061e75afa06365928fa649dd4a408c4029ca98c9a0bfda2b99e53c587c95d566375036c7f85be51b5a4e150118") << OP_CHECKSIG;
    return CreateGenesisBlock(genesisInputScript, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 210000;
        /* Note that these are not the actual activation heights, but blocks
           after them.  They are too deep in the chain to be ever reorged,
           and thus this is also fine.  */
        // FIXME: Activate BIP16 with a softfork.
        consensus.BIP16Height = 0;
        consensus.BIP34Height = 100000000;
        consensus.BIP34Hash =  	uint256S("0x1414f096a62bee2501807a9a2a97c20557df1fdfb1284f9eaff88d60defe0750");
        consensus.BIP65Height = 130000;
        consensus.BIP66Height = 130000;
        consensus.powLimit = 	uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 24 * 14 * 60 * 60; //14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 0; // Not yet enabled

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 0; // Not yet enabled

        // The best chain should have at least this much work.
        // The value is the chain work of the doichain mainnet chain at height
        // 312,290, with best block hash:
        // c98df864dce972b1948314e98e96c8a86d2c0aaa80b421fe651e203f6bab9010
        //consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000000ba50a60f8b56c7fe0");
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000010001");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("000006fdd8b4d786fd9bdde5bae9486c464e3aa4336c5f8415dfdd3fc1679134"); //250000

        consensus.nAuxpowChainId = 0x0002;
        consensus.nAuxpowStartHeight = 1;
        consensus.fStrictChainId = false;
        consensus.nLegacyBlocksBefore = 1;

        consensus.rules.reset(new Consensus::MainNetConsensus());

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xf8;
        pchMessageStart[1] = 0xb2;
        pchMessageStart[2] = 0xb2;
        pchMessageStart[3] = 0xff;
        nDefaultPort = 8338;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1522756358, 77495, 0x1f00ffff, 1, 50 * COIN);

//        consensus.hashGenesisBlock = uint256S("0x");
//
//                 // calculate Genesis Block
//                 // Reset genesis
//                 consensus.hashGenesisBlock = uint256S("0x");
//                 std::cout << std::string("Begin calculating Mainnet Genesis Block:\n");
//                 if (true && (genesis.GetHash() != consensus.hashGenesisBlock)) {
//                     LogPrintf("Calculating Mainnet Genesis Block:\n");
//                     arith_uint256 hashTarget = arith_uint256().SetCompact(genesis.nBits);
//                     uint256 hash;
//                     genesis.nNonce = 0;
//                     // This will figure out a valid hash and Nonce if you're
//                     // creating a different genesis block:
//                     // uint256 hashTarget = CBigNum().SetCompact(genesis.nBits).getuint256();
//                     // hashTarget.SetCompact(genesis.nBits, &fNegative, &fOverflow).getuint256();
//                     // while (genesis.GetHash() > hashTarget)
//                     while (UintToArith256(genesis.GetHash()) > hashTarget)
//                     {
//                         ++genesis.nNonce;
//                         if (genesis.nNonce == 0)
//                         {
//                             LogPrintf("NONCE WRAPPED, incrementing time");
//                             std::cout << std::string("NONCE WRAPPED, incrementing time:\n");
//                             ++genesis.nTime;
//                         }
//                         if (genesis.nNonce % 10000 == 0)
//                         {
//                             LogPrintf("Mainnet: nonce %08u: hash = %s \n", genesis.nNonce, genesis.GetHash().ToString().c_str());
//                             // std::cout << strNetworkID << " nonce: " << genesis.nNonce << " time: " << genesis.nTime << " hash: " << genesis.GetHash().ToString().c_str() << "\n";
//                         }
//                     }
//                     std::cout << "Mainnet ---\n";
//                     std::cout << "  nonce: " << genesis.nNonce <<  "\n";
//                     std::cout << "   time: " << genesis.nTime << "\n";
//                     std::cout << "   hash: " << genesis.GetHash().ToString().c_str() << "\n";
//                     std::cout << "   merklehash: "  << genesis.hashMerkleRoot.ToString().c_str() << "\n";
//                     // Mainnet --- nonce: 296277 time: 1390095618 hash: 000000bdd771b14e5a031806292305e563956ce2584278de414d9965f6ab54b0
//                 }
//                 std::cout << std::string("Finished calculating Mainnet Genesis Block:\n");
//

        consensus.hashGenesisBlock = genesis.GetHash();
        printf("Block: %s\n", genesis.GetHash().GetHex().c_str());
        printf("hashMerkleRoot: %s\n", genesis.hashMerkleRoot.GetHex().c_str());
        assert(consensus.hashGenesisBlock == uint256S("000006fdd8b4d786fd9bdde5bae9486c464e3aa4336c5f8415dfdd3fc1679134"));
        assert(genesis.hashMerkleRoot == uint256S("234651063df5f8b01ecc2fc3a134fa1cb9dc9da9cce0149049483ba1b1469dfb"));

        /*
Mainnet ---
  nonce: 77495
   time: 1522756358
   hash: 000006fdd8b4d786fd9bdde5bae9486c464e3aa4336c5f8415dfdd3fc1679134
   merklehash: 234651063df5f8b01ecc2fc3a134fa1cb9dc9da9cce0149049483ba1b1469dfb
Finished calculating Mainnet Genesis Block:
Block: 000006fdd8b4d786fd9bdde5bae9486c464e3aa4336c5f8415dfdd3fc1679134
hashMerkleRoot: 234651063df5f8b01ecc2fc3a134fa1cb9dc9da9cce0149049483ba1b1469dfb
*/

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.

        vSeeds.clear();      //!< DoiCoin doesn't have any DNS seeds yet!
        //vSeeds.emplace_back("nmc.seed.quisquis.de");
        //vSeeds.emplace_back("seed.nmc.markasoftware.com");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,52);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,13);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,180);
        /* FIXME: Update these below.  */
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "dc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
              {  0, uint256S("000006fdd8b4d786fd9bdde5bae9486c464e3aa4336c5f8415dfdd3fc1679134")},
			  /*    {  4032, uint256S("0000000000493b5696ad482deb79da835fe2385304b841beef1938655ddbc411")},
                {  6048, uint256S("000000000027939a2e1d8bb63f36c47da858e56d570f143e67e85068943470c9")},
                {  8064, uint256S("000000000003a01f708da7396e54d081701ea406ed163e519589717d8b7c95a5")},
                { 10080, uint256S("00000000000fed3899f818b2228b4f01b9a0a7eeee907abd172852df71c64b06")},
                { 12096, uint256S("0000000000006c06988ff361f124314f9f4bb45b6997d90a7ee4cedf434c670f")},
                { 14112, uint256S("00000000000045d95e0588c47c17d593c7b5cb4fb1e56213d1b3843c1773df2b")},
                { 16128, uint256S("000000000001d9964f9483f9096cf9d6c6c2886ed1e5dec95ad2aeec3ce72fa9")},
                { 18940, uint256S("00000000000087f7fc0c8085217503ba86f796fa4984f7e5a08b6c4c12906c05")},
                { 30240, uint256S("e1c8c862ff342358384d4c22fa6ea5f669f3e1cdcf34111f8017371c3c0be1da")},
                { 57000, uint256S("aa3ec60168a0200799e362e2b572ee01f3c3852030d07d036e0aa884ec61f203")},
                {112896, uint256S("73f880e78a04dd6a31efc8abf7ca5db4e262c4ae130d559730d6ccb8808095bf")},
                {182000, uint256S("d47b4a8fd282f635d66ce34ebbeb26ffd64c35b41f286646598abfd813cba6d9")},
                {193000, uint256S("3b85e70ba7f5433049cfbcf0ae35ed869496dbedcd1c0fafadb0284ec81d7b58")},
                {250000, uint256S("514ec75480df318ffa7eb4eff82e1c583c961aa64cce71b5922662f01ed1686a")},*/
            }
        };

        chainTxData = ChainTxData{
        	1522756358,// * UNIX timestamp of last known number of transactions
            0, // * total number of transactions between genesis and that timestamp
            //   (the tx=... number in the SetBestChain debug.log lines)
            1 // * estimated number of transactions per second after checkpoint
        };

        /* See also doc/doichainBugs.txt for more explanation on the
           historical bugs added below.  */

        /* These transactions have name outputs but a non-doichain tx version.
           They contain NAME_NEWs, which are fine, and also NAME_FIRSTUPDATE.
           The latter are not interpreted by doichaind, thus also ignore
           them for us here.  */
//        addBug(98423, "bff3ed6873e5698b97bf0c28c29302b59588590b747787c7d1ef32decdabe0d1", BUG_FULLY_IGNORE);
//        addBug(98424, "e9b211007e5cac471769212ca0f47bb066b81966a8e541d44acf0f8a1bd24976", BUG_FULLY_IGNORE);
//        addBug(98425, "8aa2b0fc7d1033de28e0192526765a72e9df0c635f7305bdc57cb451ed01a4ca", BUG_FULLY_IGNORE);

        /* These are non-doichain tx that contain just NAME_NEWs.  Those were
           handled with a special rule previously, but now they are fully
           disallowed and we handle the few exceptions here.  It is fine to
           "ignore" them, as their outputs need no special doichain handling
           before they are reused in a NAME_FIRSTUPDATE.  */
//        addBug(98318, "0ae5e958ff05ad8e273222656d98d076097def6d36f781a627c584b859f4727b", BUG_FULLY_IGNORE);
//        addBug(98321, "aca8ce46da1bbb9bb8e563880efcd9d6dd18342c446d6f0e3d4b964a990d1c27", BUG_FULLY_IGNORE);
//        addBug(98424, "c29b0d9d478411462a8ac29946bf6fdeca358a77b4be15cd921567eb66852180", BUG_FULLY_IGNORE);
//        addBug(98425, "221719b360f0c83fa5b1c26fb6b67c5e74e4e7c6aa3dce55025da6759f5f7060", BUG_FULLY_IGNORE);
//        addBug(193518, "597370b632efb35d5ed554c634c7af44affa6066f2a87a88046532d4057b46f8", BUG_FULLY_IGNORE);
//        addBug(195605, "0bb8c7807a9756aefe62c271770b313b31dee73151f515b1ac2066c50eaeeb91", BUG_FULLY_IGNORE);
//        addBug(195639, "3181930765b970fc43cd31d53fc6fc1da9439a28257d9067c3b5912d23eab01c", BUG_FULLY_IGNORE);
//        addBug(195639, "e815e7d774937d96a4b265ed4866b7e3dc8d9f2acb8563402e216aba6edd1e9e", BUG_FULLY_IGNORE);
//        addBug(195639, "cdfe6eda068e09fe760a70bec201feb041b8c660d0e98cbc05c8aa4106eae6ab", BUG_FULLY_IGNORE);
//        addBug(195641, "1e29e937b2a9e1f18af500371b8714157cf5ac7c95461913e08ce402de64ae75", BUG_FULLY_IGNORE);
//        addBug(195648, "d44ed6c0fac251931465f9123ada8459ec954cc6c7b648a56c9326ff7b13f552", BUG_FULLY_IGNORE);
//        addBug(197711, "dd77aea50a189935d0ef36a04856805cd74600a53193c539eb90c1e1c0f9ecac", BUG_FULLY_IGNORE);
//        addBug(204151, "f31875dfaf94bd3a93cfbed0e22d405d1f2e49b4d0750cb13812adc5e57f1e47", BUG_FULLY_IGNORE);

        /* This transaction has both a NAME_NEW and a NAME_FIRSTUPDATE as
           inputs.  This was accepted due to the "argument concatenation" bug.
           It is fine to accept it as valid and just process the NAME_UPDATE
           output that builds on the NAME_FIRSTUPDATE input.  (NAME_NEW has no
           special side-effect in applying anyway.)  */
//        addBug(99381, "774d4c446cecfc40b1c02fdc5a13be6d2007233f9d91daefab6b3c2e70042f05", BUG_FULLY_APPLY);

        /* These were libcoin's name stealing bugs.  */
//        addBug(139872, "2f034f2499c136a2c5a922ca4be65c1292815c753bbb100a2a26d5ad532c3919", BUG_IN_UTXO);
//        addBug(139936, "c3e76d5384139228221cce60250397d1b87adf7366086bc8d6b5e6eee03c55c7", BUG_FULLY_IGNORE);
    }

    int DefaultCheckNameDB () const
    {
        return -1;
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 210000;
        /* As before, these are not the actual activation heights but some
           blocks after them.  */
        // FIXME: Activate BIP16 with a softfork.
        consensus.BIP16Height = 10000000;
        consensus.BIP34Height = 130000;
        consensus.BIP34Hash = uint256S("0xe0a05455d89a54bb7c1b5bb785d6b1b7c5bda42ed4ce8dc19d68652ba8835954");
        consensus.BIP65Height = 130000;
        consensus.BIP66Height = 130000;
        consensus.powLimit = uint256S("000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 2 * 60 * 60; // original two weeks 14 * 24 - now 1h
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.nMinDifficultySince = 0;
        //consensus.nMinDifficultySince = 1394838000; // 15 Mar 2014
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 0; // Not yet enabled

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 0; // Not yet enabled

        // The best chain should have at least this much work.
        // The value is the chain work of the doichain testnet chain at height
        // 158,460, with best block hash:
        // cebebb916288ed48cd8a359576d900c550203883bf69fc8d5ed92c5d778a1e32
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000001c71");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0000cd7572b3ecc78b7cddf49eda95e718d4df77c236ca2e375125e111e7e9c4"); //130000

        consensus.nAuxpowChainId = 0x0003;
        consensus.nAuxpowStartHeight = 1;
        consensus.fStrictChainId = false;
        consensus.nLegacyBlocksBefore = 1;

        consensus.rules.reset(new Consensus::TestNetConsensus());

        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xba;
        pchMessageStart[2] = 0xb2;
        pchMessageStart[3] = 0xfb;
        nDefaultPort = 18338;
        nPruneAfterHeight = 1000;

        genesis = CreateTestnetGenesisBlock(1522756358, 6658, 0x1f08ffff, 1, 50 * COIN);
/*                      // calculate Genesis Block
                      // Reset genesis
            consensus.hashGenesisBlock = uint256S("0x");
                      std::cout << std::string("Begin calculating Testnet Genesis Block:\n");
                      if (true && (genesis.GetHash() != consensus.hashGenesisBlock)) {
                          LogPrintf("Calculating Testnet Genesis Block:\n");
                          arith_uint256 hashTarget = arith_uint256().SetCompact(genesis.nBits);
                          uint256 hash;
                          genesis.nNonce = 0;
                          // This will figure out a valid hash and Nonce if you're
                          // creating a different genesis block:
                          // uint256 hashTarget = CBigNum().SetCompact(genesis.nBits).getuint256();
                          // hashTarget.SetCompact(genesis.nBits, &fNegative, &fOverflow).getuint256();
                          // while (genesis.GetHash() > hashTarget)
                          while (UintToArith256(genesis.GetHash()) > hashTarget)
                          {
                              ++genesis.nNonce;
                              if (genesis.nNonce == 0)
                              {
                                  LogPrintf("NONCE WRAPPED, incrementing time");
                                  std::cout << std::string("NONCE WRAPPED, incrementing time:\n");
                                  ++genesis.nTime;
                              }
                              if (genesis.nNonce % 10000 == 0)
                              {
                                  LogPrintf("Mainnet: nonce %08u: hash = %s \n", genesis.nNonce, genesis.GetHash().ToString().c_str());
                                  // std::cout << strNetworkID << " nonce: " << genesis.nNonce << " time: " << genesis.nTime << " hash: " << genesis.GetHash().ToString().c_str() << "\n";
                              }
                          }
                          std::cout << "Testnet ---\n";
                          std::cout << "  nonce: " << genesis.nNonce <<  "\n";
                          std::cout << "   time: " << genesis.nTime << "\n";
                          std::cout << "   hash: " << genesis.GetHash().ToString().c_str() << "\n";
                          std::cout << "   merklehash: "  << genesis.hashMerkleRoot.ToString().c_str() << "\n";
                          // Mainnet --- nonce: 296277 time: 1390095618 hash: 000000bdd771b14e5a031806292305e563956ce2584278de414d9965f6ab54b0
                      }
                      std::cout << std::string("Finished calculating Testnet Genesis Block:\n");

*/

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0000cd7572b3ecc78b7cddf49eda95e718d4df77c236ca2e375125e111e7e9c4"));
        assert(genesis.hashMerkleRoot == uint256S("8de06f9a125793c3b6bfe7e3bc473ba2bb505b234af5d7e999bda03ed3f4ac34"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
       // vSeeds.emplace_back("dnsseed.test.doichain.webbtc.com", false);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        /* FIXME: Update these below.  */
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "td";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;


        checkpointData = {
            {
                {  0, uint256S("0000cd7572b3ecc78b7cddf49eda95e718d4df77c236ca2e375125e111e7e9c4")},
            }
        };

        chainTxData = ChainTxData{
        	1522756358,
            0,
            1
        };

        assert(mapHistoricBugs.empty());
    }

    int DefaultCheckNameDB () const
    {
        return -1;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Height = 0; // always enforce P2SH BIP16 on regtest
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.nMinDifficultySince = 0;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        consensus.nAuxpowStartHeight = 0;
        consensus.nAuxpowChainId = 0x0001;
        consensus.fStrictChainId = true;
        consensus.nLegacyBlocksBefore = 0;

        consensus.rules.reset(new Consensus::RegTestConsensus());

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 18445;
        nPruneAfterHeight = 1000;

        genesis = CreateTestnetGenesisBlock(1296688602, 0, 0x207fffff, 1, 50 * COIN);

/*

                      // calculate Genesis Block
                      // Reset genesis
            consensus.hashGenesisBlock = uint256S("0x");
                      std::cout << std::string("Begin calculating RegTest Genesis Block:\n");
                      if (true && (genesis.GetHash() != consensus.hashGenesisBlock)) {
                          LogPrintf("Calculating RegTest Genesis Block:\n");
                          arith_uint256 hashTarget = arith_uint256().SetCompact(genesis.nBits);
                          uint256 hash;
                          genesis.nNonce = 0;
                          // This will figure out a valid hash and Nonce if you're
                          // creating a different genesis block:
                          // uint256 hashTarget = CBigNum().SetCompact(genesis.nBits).getuint256();
                          // hashTarget.SetCompact(genesis.nBits, &fNegative, &fOverflow).getuint256();
                          // while (genesis.GetHash() > hashTarget)
                          while (UintToArith256(genesis.GetHash()) > hashTarget)
                          {
                              ++genesis.nNonce;
                              if (genesis.nNonce == 0)
                              {
                                  LogPrintf("NONCE WRAPPED, incrementing time");
                                  std::cout << std::string("NONCE WRAPPED, incrementing time:\n");
                                  ++genesis.nTime;
                              }
                              if (genesis.nNonce % 10000 == 0)
                              {
                                  LogPrintf("RegTest: nonce %08u: hash = %s \n", genesis.nNonce, genesis.GetHash().ToString().c_str());
                                  // std::cout << strNetworkID << " nonce: " << genesis.nNonce << " time: " << genesis.nTime << " hash: " << genesis.GetHash().ToString().c_str() << "\n";
                              }
                          }
                          std::cout << "RegTest ---\n";
                          std::cout << "  nonce: " << genesis.nNonce <<  "\n";
                          std::cout << "   time: " << genesis.nTime << "\n";
                          std::cout << "   hash: " << genesis.GetHash().ToString().c_str() << "\n";
                          std::cout << "   merklehash: "  << genesis.hashMerkleRoot.ToString().c_str() << "\n";
                          // Mainnet --- nonce: 296277 time: 1390095618 hash: 000000bdd771b14e5a031806292305e563956ce2584278de414d9965f6ab54b0
                      }
                      std::cout << std::string("Finished calculating RegTest Genesis Block:\n");
*/
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0231881e96d6690eb00bb69cd8e221df3564e2cd95829d47d131ed5110a34e9d"));
        assert(genesis.hashMerkleRoot == uint256S("8de06f9a125793c3b6bfe7e3bc473ba2bb505b234af5d7e999bda03ed3f4ac34"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {
                {0, uint256S("5287b3809b71433729402429b7d909a853cfac5ed40f09117b242c275e6b2d63")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "dcrt";

        assert(mapHistoricBugs.empty());
    }

    int DefaultCheckNameDB () const
    {
        return 0;
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}
