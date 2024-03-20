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

			block* Encrypt(std::string, EncMode, const std::initializer_list<const block>&);  // �����Ľ��м���
			std::string Decrypt(block*, EncMode, const std::initializer_list<const block>&);  // �����Ľ��н���

		private:
			std::array<u32, 32> mRoundKeys;  // ����Կ
			u64 blockLength;  // �����

			void setKey(const block&);
			u64 getLength() const {  // ��ȡ�����
				return this->blockLength;
			}

			void EncBlocks(const block&, block&);
			void DecBlocks(const block&, block&);

			void cbcEncBlocks(const block*, u64, const block&, block*);  // cbcģʽ����
			void ecbEncBlocks(const block*, u64, block*);  // ecbģʽ����

			void cbcDecBlocks(const block*, u64, const block&, block*);  // cbcģʽ����
			void ecbDecBlocks(const block*, u64, block*);  // ecbģʽ����


		};
	}
}
