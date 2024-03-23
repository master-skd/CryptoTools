#pragma once
#include "../Common/Defines.h"
#include<string>
#include<sstream>
#include<iostream>
#include<cstring>
#include<vector>
#include<iomanip>

namespace skd {
	namespace Crypto {
		class SHA256 {
		public:
			SHA256() = default;
			SHA256(const SHA256&) = default;

			void hash(const char*);  // 对输入的消息进行哈希
			std::string hexdigest();  // 将消息摘要转成16进制

		private:
			std::vector<u32> digest;  // 保存256位摘要
		};
	}
}
