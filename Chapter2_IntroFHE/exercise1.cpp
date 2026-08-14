#include "openfhe.h"

using namespace lbcrypto;

/* 
Write a program that fixes 2 integers a,b. Encrypt them and evalaute:
1. f1 = a+b
2. f2 = a.b
3. f3 = 5a + 6b
4. f4 = 3a^3 - a^2 + 5

*/

int main(){
    // Sample Program: Step 1: Set CryptoContext
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(2);
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    // Sample Program: Step 2: Key Generation
    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;
    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();
    // Generate the relinearization key
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);

    // Definition of the integers a and b
    std::vector<int64_t> a = {10};
    std::vector<int64_t> b = {7};
    std::vector<int64_t> five = {5};
    std::vector<int64_t> six = {6};
    std::vector<int64_t> three = {3};

    // Encode
    Plaintext a_encoded = cryptoContext->MakePackedPlaintext(a);
    Plaintext b_encoded = cryptoContext->MakePackedPlaintext(b);
    Plaintext five_encoded = cryptoContext->MakePackedPlaintext(five);
    Plaintext six_encoded = cryptoContext->MakePackedPlaintext(six);
    Plaintext three_encoded = cryptoContext->MakePackedPlaintext(three);

    // Cypher
    auto a_cyphered = cryptoContext->Encrypt(keyPair.publicKey, a_encoded);
    auto b_cyphered = cryptoContext->Encrypt(keyPair.publicKey, b_encoded);

    // Operations
    auto f1 = cryptoContext->EvalAdd(a_cyphered, b_cyphered);
    auto f2 = cryptoContext->EvalMult(a_cyphered, b_cyphered);
    auto f3 = cryptoContext->EvalAdd(cryptoContext->EvalMult(a_cyphered, five_encoded),cryptoContext->EvalMult(b_cyphered, six_encoded));
    auto f4 = cryptoContext->EvalAdd(cryptoContext->EvalSub(cryptoContext->EvalMult(cryptoContext->EvalMult(a_cyphered, a_cyphered), cryptoContext->EvalMult(a_cyphered, three_encoded)), cryptoContext->EvalMult(a_cyphered, a_encoded)), five_encoded);

    // Decrypt
    Plaintext f1_decoded;
    Plaintext f2_decoded;
    Plaintext f3_decoded;
    Plaintext f4_decoded;
    cryptoContext->Decrypt(keyPair.secretKey, f1, &f1_decoded);
    cryptoContext->Decrypt(keyPair.secretKey, f2, &f2_decoded);
    cryptoContext->Decrypt(keyPair.secretKey, f3, &f3_decoded);
    cryptoContext->Decrypt(keyPair.secretKey, f4, &f4_decoded);

    // Print results
    std::cout << "f1 = a + b = " << f1_decoded << std::endl;
    std::cout << "f2 = a * b = " << f2_decoded << std::endl;
    std::cout << "f3 = 5a + 6b = " << f3_decoded << std::endl;
    std::cout << "f4 = 3a^3 - a^2 + 5 = " << f4_decoded << std::endl;

    return 0;
    // g++ .\exercise1.cpp -std=gnu++17 -I"C:\mingw2\home\User\openfhe-development\src\pke\include" -I"C:\mingw2\home\User\openfhe-development\src\core\include" -I"C:\mingw2\home\User\openfhe-development\src\binfhe\include" -I"C:\mingw2\home\User\openfhe-development\third-party\cereal\include" -I"C:\mingw2\home\User\openfhe-development\build\src\core" -I"C:\mingw2\home\User\openfhe-development\build\src\pke" -I"C:\mingw2\home\User\openfhe-development\build\src\binfhe" -I"C:\mingw2\home\User\openfhe-development\build" -I"C:\mingw2\usr\local\include\openfhe" -I"C:\mingw2\usr\local\include\openfhe\pke" -I"C:\mingw2\usr\local\include\openfhe\core" -L"C:\mingw2\home\User\openfhe-development\build\lib" -L"C:\mingw2\usr\local\lib" -lOPENFHEpke -lOPENFHEcore -lOPENFHEbinfhe -o exercise1.exe
}