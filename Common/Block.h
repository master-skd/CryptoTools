#pragma once
#include<array>
#include<cstdint>
#include<iostream>
#include "Defines.h"

namespace skd {
	namespace Crypto {
		using bytes = std::array<uint8_t, 16>;

		struct block {
			uint8_t mData[16];  // 128比特一个分组块, 从低位到高位

			block() = default;
			block(const block&) = default;
			block(uint8_t e15, uint8_t e14, uint8_t e13, uint8_t e12, uint8_t e11, uint8_t e10, uint8_t e9, uint8_t e8, uint8_t e7, uint8_t e6, uint8_t e5, uint8_t e4, uint8_t e3, uint8_t e2, uint8_t e1, uint8_t e0) {
				mData[0] = e0;
				mData[1] = e1;
				mData[2] = e2;
				mData[3] = e3;
				mData[4] = e4;
				mData[5] = e5;
				mData[6] = e6;
				mData[7] = e7;
				mData[8] = e8;
				mData[9] = e9;
				mData[10] = e10;
				mData[11] = e11;
				mData[12] = e12;
				mData[13] = e13;
				mData[14] = e14;
				mData[15] = e15;

			}
			template<typename T, typename Enable = typename std::enable_if<(sizeof(T) <= 16) &&(16 % sizeof(T) == 0)>::type>  // 保证128比特，即16字节
			block(std::array<T, 16 / sizeof(T)>& arr) {  // 数组中元素顺序为从高位到低位
				auto size = 16 / sizeof(T);  //
				for (int i = size - 1; i >= 0; i--) {
					uint8_t* byte = (uint8_t*)&arr[i];
					for (auto j = 0; j < sizeof(T); j++)
						mData[16 - (i + 1) * sizeof(T) + j] = *(byte + j);
				}
			}

			unsigned char* data() const {
				return (unsigned char*)mData;
			}

			template<typename T>
			typename std::enable_if<(sizeof(T) <= 16) && (16 % sizeof(T) == 0), std::array<T, 16 / sizeof(T)>>::type get() const {
				auto data = mData;
				std::array<T, 16 / sizeof(T)> output = {};
				auto size = 16 / sizeof(T);
				for (int i = 0; i < size; i++) {
					output[i] = *((T*)(data + i * sizeof(T)));
				}
				return output;
			}

			block cc_xor_128(const block& rhs) const {
				auto ret = get<uint8_t>();
				auto rhsa = rhs.get<uint8_t>();
				for (int i = 0; i < 16; i++) {
					ret[i] ^= rhsa[i];
				}
				return block(ret[15], ret[14], ret[13], ret[12], ret[11], ret[10], ret[9], ret[8], ret[7], ret[6], ret[5], ret[4], ret[3], ret[2], ret[1], ret[0]);
			}
			block cc_and_128(const block& rhs) const {
				auto ret = get<uint8_t>();
				auto rhsa = rhs.get<uint8_t>();
				for (int i = 0; i < 16; i++) {
					ret[i] &= rhsa[i];
				}
				return block(ret[15], ret[14], ret[13], ret[12], ret[11], ret[10], ret[9], ret[8], ret[7], ret[6], ret[5], ret[4], ret[3], ret[2], ret[1], ret[0]);
			}
			block cc_or_128(const block& rhs) const {
				auto ret = get<uint8_t>();
				auto rhsa = rhs.get<uint8_t>();
				for (int i = 0; i < 16; i++) {
					ret[i] |= rhsa[i];
				}
				return block(ret[15], ret[14], ret[13], ret[12], ret[11], ret[10], ret[9], ret[8], ret[7], ret[6], ret[5], ret[4], ret[3], ret[2], ret[1], ret[0]);
			}
			
			// 重载异或、按位与、按位或、取反运算符
			block operator^ (const block& rhs) const {
				return cc_xor_128(rhs);
			}
			block operator& (const block& rhs) const {
				return cc_and_128(rhs);
			}
			block operator| (const block& rhs) const {
				return cc_or_128(rhs);
			}
			block operator~ () const {
				return *this ^ block(-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1);
			}
			
			block& operator^= (const block& rhs) {
				*this = *this ^ rhs;
				return *this;
			}
			block& operator&= (const block& rhs) {
				*this = *this & rhs;
				return *this;
			}
			block& operator|= (const block& rhs) {
				*this = *this | rhs;
				return *this;
			}
			
			block cc_andnot_128(const block& rhs) {
				return ~(*this ^ rhs);
			}
			block andnot_128(const block& rhs) {
				return cc_andnot_128(rhs);
			}
			
			// 重载输出运算符
			friend std::ostream& operator<< (std::ostream& os, const block& rhs) {
				for (int i = 0; i < 16; i++) {
					os << int(rhs.mData[15 - i]) << " ";
				}
				return os;
			}
		};

		// 仅适用于分组长度为128比特的密码算法
		static block* toBlock(std::string msg) {  // 将一个消息转化为block数组，采用PKSC7填充
			auto length = msg.length();  // 首先计算消息长度
			size_t blockLength = length / 16 + 1;  // 块长度
			block* msgBlock = new block[blockLength];
			size_t remainder = length % 16, padlen = 16 - remainder;
			char pad[16];  // 用于填充
			for (size_t i = 0; i < padlen; i++)
				pad[i] = padlen;
			msg += std::string(pad);
			for (int i = 0; i < blockLength; i++)
				msgBlock[i] = block(msg[i * 16 + 15], msg[i * 16 + 14], msg[i * 16 + 13], msg[i * 16 + 12], msg[i * 16 + 11], msg[i * 16 + 10], msg[i * 16 + 9], msg[i * 16 + 8], msg[i * 16 + 7], msg[i * 16 + 6], msg[i * 16 + 5], msg[i * 16 + 4], msg[i * 16 + 3], msg[i * 16 + 2], msg[i * 16 + 1], msg[i * 16]);
			// 对最后一个消息块进行填充
			return msgBlock;
		}
	}
}
