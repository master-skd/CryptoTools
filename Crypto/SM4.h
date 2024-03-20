#pragma once
#include "../Common/Block.h"
#include "../Common/Defines.h"
#include<sstream>

namespace skd {
	namespace Crypto {
		class SM4 {
		public:
			SM4() = default;
			SM4(const SM4&) = default;
			SM4(const block&);

			block* Encrypt(std::string, EncMode, const std::initializer_list<const block>&);  // 对明文进行加密
			std::string Decrypt(block*, EncMode, const std::initializer_list<const block>&);  // 对密文进行解密

		private:
			std::array<u32, 32> mRoundKeys;  // 轮密钥
			u64 blockLength;  // 块个数

			void setKey(const block&);
			u64 getLength() const {  // 获取块个数
				return this->blockLength;
			}

			void EncBlocks(const block&, block&);
			void DecBlocks(const block&, block&);

			void cbcEncBlocks(const block*, u64, const block&, block*);  // cbc模式加密
			void ecbEncBlocks(const block*, u64, block*);  // ecb模式加密

			void cbcDecBlocks(const block*, u64, const block&, block*);  // cbc模式解密
			void ecbDecBlocks(const block*, u64, block*);  // ecb模式解密


		};
	}
}
