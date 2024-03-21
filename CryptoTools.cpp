// CryptoTools.cpp: 定义应用程序的入口点。
//

#include "CryptoTools.h"
using namespace skd::Crypto;

int main() {
	/*std::string msg = "Hello, my name is skd";
	std::array<u64, 2> userKey = { 0x0f0e0d0c0b0a0908, 0x0706050403020100 };
	std::array<u64, 2> I = { 0x0f0e0d0c0b0a0908, 0x0706050403020100 };
	block Key = block(userKey), Iv = block(I);
	AES a = AES(Key);
	auto cipher = a.Encrypt(msg, EncMode::CBC_MODE, { Iv });
	std::string plain1 = a.Decrypt(cipher, EncMode::CBC_MODE, { Iv });
	
	SM4 s = SM4(Key);
	auto cipher2 = s.Encrypt(msg, EncMode::CBC_MODE, { Iv });
	std::string plain2 = a.Decrypt(cipher, EncMode::CBC_MODE, { Iv });

	std::cout << plain1 << std::endl << plain2 << std::endl;*/

	const char* msg = "hello, world! my name is skd, i love ml";
	SHA256 s = SHA256();
	s.hash(msg);
	auto hashmsg = s.hexdigest();
	std::cout << hashmsg << std::endl;

	return 0;
}
