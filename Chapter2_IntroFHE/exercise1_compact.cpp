#include "openfhe.h"

using namespace lbcrypto;

/*
Same program as exercise1.cpp -- fix 2 integers a,b, encrypt them and evaluate:
1. f1 = a+b
2. f2 = a.b
3. f3 = 5a + 6b
4. f4 = 3a^3 - a^2 + 5

Written compactly, to compare against exercise1.cpp. The differences:

  - ciphertext +, -, * are overloaded and forward to EvalAdd/EvalSub/EvalMult
    (see openfhe src/pke/include/ciphertext.h). Ciphertext-ciphertext only:
    mixing in a plaintext still needs the explicit Eval* call.
  - an `enc` lambda replaces the five MakePackedPlaintext blocks. EvalMult takes
    ConstPlaintext& (const, binds a temporary) but EvalAdd/EvalSub take a
    non-const Plaintext&, so their operands must be named variables.
  - SetLength(1) trims the decrypted slot vector, which otherwise prints the
    full ring dimension worth of trailing zeros.
  - f4 is factored as a^2(3a - 1) + 5: same multiplicative depth 2, one fewer
    multiplication, and it fits on one line.
*/

int main() {
    // Step 1: CryptoContext
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(2);
    auto cc = GenCryptoContext(parameters);
    for (auto feature : {PKE, KEYSWITCH, LEVELEDSHE})
        cc->Enable(feature);

    // Step 2: Key generation (public/private pair + relinearization key)
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    // Step 3: Encode and encrypt
    auto enc = [&](int64_t v) { return cc->MakePackedPlaintext({v}); };
    Plaintext one = enc(1), five = enc(5);  // named: EvalAdd/EvalSub need lvalues

    auto a = cc->Encrypt(keys.publicKey, enc(10));
    auto b = cc->Encrypt(keys.publicKey, enc(7));

    // Step 4: Operations
    auto a2    = a * a;                                      // depth 1
    auto inner = cc->EvalSub(cc->EvalMult(a, enc(3)), one);  // 3a - 1, depth 0

    std::vector<std::pair<std::string, Ciphertext<DCRTPoly>>> results = {
        {"f1 = a + b         ", a + b},
        {"f2 = a * b         ", a * b},
        {"f3 = 5a + 6b       ", cc->EvalMult(a, enc(5)) + cc->EvalMult(b, enc(6))},
        {"f4 = 3a^3 - a^2 + 5", cc->EvalAdd(a2 * inner, five)},  // depth 2
    };

    // Step 5: Decrypt and print
    for (auto& [label, ciphertext] : results) {
        Plaintext decoded;
        cc->Decrypt(keys.secretKey, ciphertext, &decoded);
        decoded->SetLength(1);
        std::cout << label << " = " << decoded << std::endl;
    }

    return 0;
    // g++ .\exercise1_compact.cpp -std=gnu++17 -I"C:\mingw2\home\User\openfhe-development\src\pke\include" -I"C:\mingw2\home\User\openfhe-development\src\core\include" -I"C:\mingw2\home\User\openfhe-development\src\binfhe\include" -I"C:\mingw2\home\User\openfhe-development\third-party\cereal\include" -I"C:\mingw2\home\User\openfhe-development\build\src\core" -I"C:\mingw2\home\User\openfhe-development\build\src\pke" -I"C:\mingw2\home\User\openfhe-development\build\src\binfhe" -I"C:\mingw2\home\User\openfhe-development\build" -I"C:\mingw2\usr\local\include\openfhe" -I"C:\mingw2\usr\local\include\openfhe\pke" -I"C:\mingw2\usr\local\include\openfhe\core" -L"C:\mingw2\home\User\openfhe-development\build\lib" -L"C:\mingw2\usr\local\lib" -lOPENFHEpke -lOPENFHEcore -lOPENFHEbinfhe -o exercise1_compact.exe
}
