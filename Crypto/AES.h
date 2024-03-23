#pragma once
#include "../Common/Defines.h"
#include<cstring>
#include<string>
#include<initializer_list>
#include<stdexcept>
#include<sstream>

namespace skd {
	namespace Crypto {
		class AES {
		public:
			static const u64 rounds = 10;  // 默认轮数为10轮
			AES() = default;
			AES(const AES&) = default;
			AES(const block&);  // 通过密钥来初始化该类对象

			u64 getLength() const {  // 获取块个数
				return this->blockLength;
			}

			block* Encrypt(std::string, EncMode, const std::initializer_list<const block>&);  // 对明文进行加密
			std::string Decrypt(block*, EncMode, const std::initializer_list<const block>&);  // 对密文进行解密

		private:
			std::array<block, rounds + 1> mRoundKeys;  // 扩展出的轮密钥
			u64 blockLength;  // 块个数

			void setKey(const block&);  // 设置加密所用密钥

			void EncBlocks(const block&, block&);  // 对一个分组块的加密
			void DecBlocks(const block&, block&);  // 对最后一个分组块的解密

			void cbcEncBlocks(const block*, u64, const block&, block*);  // cbc模式加密
			void ecbEncBlocks(const block*, u64, block*);  // ecb模式加密

			void cbcDecBlocks(const block*, u64, const block&, block*);  // cbc模式解密
			void ecbDecBlocks(const block*, u64, block*);  // ecb模式解密
		};
	}
}
