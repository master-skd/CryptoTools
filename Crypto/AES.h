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
			static const u64 rounds = 10;  // Ĭ������Ϊ10��
			AES() = default;
			AES(const AES&) = default;
			AES(const block&);  // ͨ����Կ����ʼ���������

			u64 getLength() const {  // ��ȡ�����
				return this->blockLength;
			}

			block* Encrypt(std::string, EncMode, const std::initializer_list<const block>&);  // �����Ľ��м���
			std::string Decrypt(block*, EncMode, const std::initializer_list<const block>&);  // �����Ľ��н���

		private:
			std::array<block, rounds + 1> mRoundKeys;  // ��չ��������Կ
			u64 blockLength;  // �����

			void setKey(const block&);  // ���ü���������Կ

			void EncBlocks(const block&, block&);  // ��һ�������ļ���
			void DecBlocks(const block&, block&);  // �����һ�������Ľ���

			void cbcEncBlocks(const block*, u64, const block&, block*);  // cbcģʽ����
			void ecbEncBlocks(const block*, u64, block*);  // ecbģʽ����

			void cbcDecBlocks(const block*, u64, const block&, block*);  // cbcģʽ����
			void ecbDecBlocks(const block*, u64, block*);  // ecbģʽ����
		};
	}
}
