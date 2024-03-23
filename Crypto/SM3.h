#pragma once
#include "../Common/Defines.h"
#include<string>
#include<vector>

namespace skd {
	namespace Crypto {
		class SM3 {
			SM3() = default;
			SM3(const SM3&) = default;

			void hash(const char*);
			std::string hexdigest();

		};
	}
}
