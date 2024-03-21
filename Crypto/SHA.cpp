#include "SHA.h"

namespace skd {
	namespace Crypto {
		static const u32 hashInit[8] = {  // 8个哈希初值
			0x6a09e667,
			0xbb67ae85,
			0x3c6ef372,
			0xa54ff53a,
			0x510e527f,
			0x9b05688c,
			0x1f83d9ab,
			0x5be0cd19
		};

		static const u32 hashConst[64] = {  // 64个哈希常量
			0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
			0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
			0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
			0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
			0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
			0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
			0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
			0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
		};

		void padding(std::vector<unsigned char>& msg, size_t& length) {  // 对消息进行填充
			auto len = length * 8;
			msg.push_back(0x80);
			length++;
			for (; length % 64 != 56; length++)
				msg.push_back(0x00);
			std::vector<unsigned char> l(8, 0);
			for (int i = 7; i >= 0; i--) {
				l[i] = len & 0xff;
				len >>= 8;
			}
			msg.insert(msg.end(), l.begin(), l.end());
			length += 8;
		}

		inline u32 Ch(u32 x, u32 y, u32 z) {
			return (x & y) ^ (~x & z);
		}
		inline u32 Maj(u32 x, u32 y, u32 z) {
			return (x & z) ^ (x & y) ^ (y & z);
		}

		inline u32 ShiftRight(u32 x, int n) {  // 循环右移n位
			return (x >> n) | (x << (32 - n));
		}

		inline u32 Sig0(u32 x) {
			return ShiftRight(x, 2) ^ ShiftRight(x, 13) ^ ShiftRight(x, 22);
		}
		inline u32 Sig1(u32 x) {
			return ShiftRight(x, 6) ^ ShiftRight(x, 11) ^ ShiftRight(x, 25);
		}
		inline u32 sig0(u32 x) {
			return ShiftRight(x, 7) ^ ShiftRight(x, 18) ^ (x >> 3);
		}
		inline u32 sig1(u32 x) {
			return ShiftRight(x, 17) ^ ShiftRight(x, 19) ^ (x >> 10);
		}

		std::vector<u32> getBlocks(const std::vector<u32>& msg) {  // 由初始消息块计算新消息块
			std::vector<u32> output(msg.begin(), msg.end());
			for (size_t j = 16; j < 64; j++)
				output.push_back(sig1(output[j - 2]) + output[j - 7] + sig0(output[j - 15] + output[j - 16]));
			return output;
		}

		void SHA256::hash(const char* msg) {
			auto size = strlen(msg);  // 统计消息的字节数
			std::vector<unsigned char> m(msg, msg + size);  // 将消息拷贝到一个容器中，方便操作和填充
			padding(m, size);  // 首先对消息进行填充
			auto blockLen = size * 8 / 512;
			std::vector<u32> H;  // 存储中间哈希值
			for (size_t i = 0; i < blockLen; i++) {
				if (i == 0)  // 第一个块需要用到哈希初值
					H.assign(hashInit, hashInit + 8);
				std::vector<u32> M;  // 当前消息块，16个字
				for (size_t j = 0; j < 16; j++) {
					M.push_back((msg[i * 64 + j * 4]) | (msg[i * 64 + 1 + j * 4] << 8) | (msg[i * 64 + 2 + j * 4] << 16) | (msg[i * 64 + 3 + j * 4] << 24));
				}
				auto a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];  // 用上一个哈希块来进行初始化
				auto W = getBlocks(M);  // 获取消息块
				for (size_t j = 0; j < 64; j++) {
					u32 T1 = h + Sig1(e) + Ch(e, f, g) + hashConst[j] + W[j];
					u32 T2 = Sig0(a) + Maj(a, b, c);
					h = g;
					g = f;
					f = e;
					e = d + T1;
					d = c;
					c = b;
					b = a;
					a = T1 + T2;
				}
				H[0] += a;
				H[1] += b;
				H[2] += c;
				H[3] += d;
				H[4] += e;
				H[5] += f;
				H[6] += g;
				H[7] += h;
			}
			digest.assign(H.begin(), H.end());
		}

		std::string SHA256::hexdigest() {
			std::stringstream ss;
			for (auto byte : digest) {
				ss << std::hex << std::setw(8) << std::setfill('0') << byte;
			}
			return ss.str();
		}
	}
}
