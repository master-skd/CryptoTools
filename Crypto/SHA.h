#pragma once
#include<string>
#include<sstream>
#include<iostream>
#include "../Common/Defines.h"
#include<cstring>
#include<vector>

namespace skd {
	namespace Crypto {
		class SHA256 {
		public:
			SHA256() = default;
			SHA256(const SHA256&) = default;

			void hash(const char*);  // 对输入的消息进行哈希
			std::string hexdigest();  // 将消息摘要转成16进制

		private:
			unsigned char digest[32];  // 保存256位摘要
		};

		class SHA3 {

		};
	}
}
