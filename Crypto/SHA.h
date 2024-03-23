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

			void hash(const char*);  // ���������Ϣ���й�ϣ
			std::string hexdigest();  // ����ϢժҪת��16����

		private:
			std::vector<u32> digest;  // ����256λժҪ
		};
	}
}
