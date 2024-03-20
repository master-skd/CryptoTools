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

			void hash(const char*);  // ���������Ϣ���й�ϣ
			std::string hexdigest();  // ����ϢժҪת��16����

		private:
			unsigned char digest[32];  // ����256λժҪ
		};

		class SHA3 {

		};
	}
}
