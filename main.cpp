#include "include/PVWToBFVSeal.h"
#include "include/global.h"
#include "include/regevEncryption.h"
#include "include/SealUtils.h"
#include "include/client.h"
#include "include/LoadAndSaveUtils.h"
#include "include/timeHumanizer.h"
#include <thread>

using namespace seal;

vector<vector<uint64_t>> preparingTransactionsFormal(PVWpk &pk,
                                                     int numOfTransactions, int pertinentMsgNum,
                                                     const PVWParam &params, bool formultitest = false)
{
    srand(time(NULL));

    vector<int> msgs(numOfTransactions);
    vector<vector<uint64_t>> ret;
    vector<int> zeros(params.ell, 0);

    for (int i = 0; i < pertinentMsgNum;)
    {
        auto temp = rand() % numOfTransactions;
        while (msgs[temp])
        {
            temp = rand() % numOfTransactions;
        }
        msgs[temp] = 1;
        i++;
    }

    cout << "Expected Message Indices: ";

    for (int i = 0; i < numOfTransactions; i++)
    {
        PVWCiphertext tempclue;
        if (msgs[i])
        {
            cout << i << " ";
            PVWEncPK(tempclue, zeros, pk, params);
            ret.push_back(loadDataSingle(i));
            expectedIndices.push_back(uint64_t(i));
        }
        else
        {
            auto sk2 = PVWGenerateSecretKey(params);
            PVWEncSK(tempclue, zeros, sk2, params);
        }

        saveClues(tempclue, i);
    }
    cout << endl;
    return ret;
}

// Phase 1, obtaining PV's
Ciphertext serverOperations1obtainPackedSIC(vector<PVWCiphertext> &SICPVW, vector<Ciphertext> switchingKey, const RelinKeys &relin_keys,
                                            const GaloisKeys &gal_keys, const size_t &degree, const SEALContext &context, const PVWParam &params, const int numOfTransactions)
{
    Evaluator evaluator(context);

    vector<Ciphertext> packedSIC(params.ell);
    computeBplusASPVWOptimized(packedSIC, SICPVW, switchingKey, gal_keys, context, params);

    int rangeToCheck = 850; // range check is from [-rangeToCheck, rangeToCheck-1]
    newRangeCheckPVW(packedSIC, rangeToCheck, relin_keys, degree, context, params);

    return packedSIC[0];
}

// check OMD detection key size
// We are:
//      1. packing PVW sk into ell ciphertexts
//      2. using seed mode in SEAL
void OMDlevelspecificDetectKeySize()
{
    auto params = PVWParam(450, 65537, 1.3, 16000, 4);
    auto sk = PVWGenerateSecretKey(params);
    cout << "Finishing generating sk for PVW cts\n";
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = poly_modulus_degree_glb;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree, {28,
                                                                    39, 60, 60, 60,
                                                                    60, 60, 60, 60, 60, 60,
                                                                    32, 30, 60});
    parms.set_coeff_modulus(coeff_modulus);
    parms.set_plain_modulus(65537);

    prng_seed_type seed;
    for (auto &i : seed)
    {
        i = random_uint64();
    }
    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    parms.set_random_generator(rng);

    SEALContext context(parms, true, sec_level_type::none);
    print_parameters(context);
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);
    GaloisKeys gal_keys;

    seal::Serializable<PublicKey> pk = keygen.create_public_key();
    seal::Serializable<RelinKeys> rlk = keygen.create_relin_keys();
    stringstream streamPK, streamRLK, streamRTK;
    auto reskeysize = pk.save(streamPK);
    reskeysize += rlk.save(streamRLK);
    reskeysize += keygen.create_galois_keys(vector<int>({1})).save(streamRTK);

    public_key.load(context, streamPK);
    relin_keys.load(context, streamRLK);
    gal_keys.load(context, streamRTK);
    vector<seal::Serializable<Ciphertext>> switchingKeypacked = genSwitchingKeyPVWPacked(context, poly_modulus_degree, public_key, secret_key, sk, params);
    stringstream data_stream;
    for (size_t i = 0; i < switchingKeypacked.size(); i++)
        reskeysize += switchingKeypacked[i].save(data_stream);
    cout << "Detection Key Size: " << reskeysize << " bytes" << endl;
}

void OMD1p()
{
    chrono::high_resolution_clock::time_point time_start, time_end;

    // CREATING TXNS
    cout << "Creating database of " << numOfTransactions_glb << " txns... " << flush;
    time_start = chrono::high_resolution_clock::now();

    size_t poly_modulus_degree = poly_modulus_degree_glb;

    int numOfTransactions = numOfTransactions_glb; // 1 << 19
    createDatabase(numOfTransactions, 306); // one time; note that this 306 represents 612 bytes because each slot can contain 2 bytes

    time_end = chrono::high_resolution_clock::now();
    cout << "done in " << formatDuration(time_end - time_start) << endl;
    // CREATING TXNS DONE

    // step 1. generate PVW sk
    // recipient side
    cout << "Generating sk for PVW cts... " << flush;
    time_start = chrono::high_resolution_clock::now();

    auto params = PVWParam(450, 65537, 1.3, 16000, 1);
    auto sk = PVWGenerateSecretKey(params);
    auto pk = PVWGeneratePublicKey(params, sk);

    time_end = chrono::high_resolution_clock::now();
    cout << "done in " << formatDuration(time_end - time_start) << endl << endl;

    // step 2. prepare transactions
    cout << "Preparing txns... " << endl;
    time_start = chrono::high_resolution_clock::now();

    auto expected = preparingTransactionsFormal(pk, numOfTransactions, num_of_pertinent_msgs_glb, params);

    time_end = chrono::high_resolution_clock::now();
    cout << "Transactions with " << expected.size() << " pertinent messages prepared in " << formatDuration(time_end - time_start) << endl << endl;

    // step 3. generate detection key
    // recipient side
    cout << "Generating detection keys... " << endl;
    time_start = chrono::high_resolution_clock::now();

    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree, {28,
                                                                    39, 60, 60, 60,
                                                                    60, 60, 60, 60, 60, 60,
                                                                    32, 30, 60});
    parms.set_coeff_modulus(coeff_modulus);
    parms.set_plain_modulus(65537);

    prng_seed_type seed;
    for (auto &i : seed)
    {
        i = random_uint64();
    }
    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    parms.set_random_generator(rng);

    SEALContext context(parms, true, sec_level_type::none);
    print_parameters(context);
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    vector<Ciphertext> switchingKey;
    Ciphertext packedSIC;
    switchingKey.resize(params.ell);
    // Generated BFV ciphertexts encrypting PVW secret keys
    genSwitchingKeyPVWPacked(switchingKey, context, poly_modulus_degree, public_key, secret_key, sk, params);

    vector<vector<PVWCiphertext>> SICPVW_multicore(numcores);
    vector<vector<vector<uint64_t>>> payload_multicore(numcores);
    vector<int> counter(numcores);

    GaloisKeys gal_keys;
    vector<int> stepsfirst = {1};
    // only one rot key is needed for full level
    keygen.create_galois_keys(stepsfirst, gal_keys);

    time_end = chrono::high_resolution_clock::now();
    cout << "Detection keys generated in " << formatDuration(time_end - time_start) << endl << endl;


    vector<vector<Ciphertext>> packedSICfromPhase1(numcores, vector<Ciphertext>(numOfTransactions / numcores / poly_modulus_degree)); // Assume numOfTransactions/numcores/poly_modulus_degree is integer, pad if needed

    //NTL::SetNumThreads(numcores);
    SecretKey secret_key_blank;

    time_start = chrono::high_resolution_clock::now();

    MemoryPoolHandle my_pool = MemoryPoolHandle::New();
    auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
    //NTL_EXEC_RANGE(numcores, first, last);
    int first = 0; int last = numcores;
    for (int i = first; i < last; i++)
    {
        counter[i] = numOfTransactions / numcores * i;

        chrono::high_resolution_clock::time_point time_start_batch, time_end_batch;
        size_t j = 0;

        while (j < numOfTransactions / numcores / poly_modulus_degree)
        {
            time_start_batch = chrono::high_resolution_clock::now();
            cout << "OMD, Batch " << j << "... " << flush;

            loadClues(SICPVW_multicore[i], counter[i], counter[i] + poly_modulus_degree, params);
            packedSICfromPhase1[i][j] = serverOperations1obtainPackedSIC(SICPVW_multicore[i], switchingKey, relin_keys, gal_keys,
                                                                         poly_modulus_degree, context, params, poly_modulus_degree);
            j++;
            counter[i] += poly_modulus_degree;
            SICPVW_multicore[i].clear();

            time_end_batch = chrono::high_resolution_clock::now();
            cout << "done in " << formatDuration(time_end_batch - time_start_batch) << endl;
        }
    }
    //NTL_EXEC_RANGE_END;
    MemoryManager::SwitchProfile(std::move(old_prof));

    cout << endl;

    int determinCounter = 0;
    Ciphertext res;
    for (size_t i = 0; i < packedSICfromPhase1.size(); i++)
    {
        for (size_t j = 0; j < packedSICfromPhase1[i].size(); j++)
        {
            Plaintext plain_matrix;
            vector<uint64_t> pod_matrix(poly_modulus_degree, 1 << determinCounter);
            batch_encoder.encode(pod_matrix, plain_matrix);
            if ((i == 0) && (j == 0))
            {
                evaluator.multiply_plain(packedSICfromPhase1[i][j], plain_matrix, res);
            }
            else
            {
                evaluator.multiply_plain_inplace(packedSICfromPhase1[i][j], plain_matrix);
                evaluator.add_inplace(res, packedSICfromPhase1[i][j]);
            }
            determinCounter++;
        }
    }

    while (context.last_parms_id() != res.parms_id())
        evaluator.mod_switch_to_next_inplace(res);

    time_end = chrono::high_resolution_clock::now();
    cout << "Detector running time: " << formatDuration(time_end - time_start) << endl;

    // step 5. receiver decoding
    time_start = chrono::high_resolution_clock::now();
    auto realres = decodeIndicesOMD(res, numOfTransactions, poly_modulus_degree, secret_key, context);
    time_end = chrono::high_resolution_clock::now();
    cout << "Recipient running time: " << formatDuration(time_end - time_start) << endl;

    bool allflags = true;
    for (size_t i = 0; i < expectedIndices.size(); i++)
    {
        bool flag = false;
        for (size_t j = 0; j < realres.size(); j++)
        {
            if (expectedIndices[i] == realres[j])
            {
                flag = true;
                break;
            }
        }
        if (!flag)
        {
            cout << expectedIndices[i] << " not found" << endl;
            allflags = false;
        }
    }

    if (allflags)
        cout << "Result is correct!" << endl;
    else
        cout << "Overflow" << endl;

    for (size_t i = 0; i < res.size(); i++)
    {
        // ???
    }
}

int main()
{

    cout << "+------------------------------------+" << endl;
    cout << "| Demos                              |" << endl;
    cout << "+------------------------------------+" << endl;
    cout << "| 1. OMD1p Detection Key Size        |" << endl;
    cout << "| 2. OMD1p                           |" << endl;
    cout << "| 0. Exit                            |" << endl;
    cout << "+------------------------------------+" << endl;

    int selection = 0;
    bool valid = true;
    do
    {
        cout << endl
             << "> Run demos (1 ~ 9) or exit (0): ";
        if (!(cin >> selection))
        {
            valid = false;
        }
        else if (selection < 0 || selection > 2)
        {
            valid = false;
        }
        else
        {
            valid = true;
        }
        if (!valid)
        {
            cout << "  [Beep~~] valid option: type 0 ~ 9" << endl;
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
        }
    } while (!valid);

    switch (selection)
    {
    case 1:
        OMDlevelspecificDetectKeySize();
        break;

    case 2:
        numcores = 1;
        OMD1p();
        break;

    case 0:
        return 0;
    }
}
