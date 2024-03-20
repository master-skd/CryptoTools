#include "AES.h"

namespace skd {
	namespace Crypto {
        // S盒
		static const u8 sBox[256] = {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
		};
        // 逆S盒
        static const u8 rsBox[256] = {
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        };
        // 轮常量
        static const u8 Rcon[AES::rounds + 1] = {
            0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
        };

        AES::AES(const block& userKey) {
            setKey(userKey);
        }

        inline u8 getSBoxValue(int num) { return sBox[num]; }
        inline u8 getSBoxInvert(int num) { return rsBox[num]; }

        inline u8 xtime(u8 x) {  // 有限域中的元素乘以x
            return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
        }
        static inline u8 Multiply(u8 x, u8 y) {  // 有限域中的元素相乘
            return (
                ((y & 1) * x) ^
                (((y >> 1) & 1) * xtime(x)) ^
                (((y >> 2) & 1) * xtime(xtime(x))) ^
                (((y >> 3) & 1) * xtime(xtime(xtime(x)))) ^
                (((y >> 4) & 1) * xtime(xtime(xtime(xtime(x))))) ^
                (((y >> 5) & 1) * xtime(xtime(xtime(xtime(xtime(x)))))) ^
                (((y >> 6) & 1) * xtime(xtime(xtime(xtime(xtime(xtime(x))))))) ^
                (((y >> 7) & 1) * xtime(xtime(xtime(xtime(xtime(xtime(xtime(x))))))))
                );
        }

        void SubBytes(block& state_) {
            auto state = state_.data();
            for (int i = 0; i < 16; i++)
                state[i] = getSBoxValue(state[i]);
        }
        void ShiftRows(block& state_) {
            auto state = state_.data();
            u8 temp;
            // 第一行不动
            // 第二行循环左移1个字节
            temp = state[1];
            state[1] = state[5];
            state[5] = state[9];
            state[9] = state[13];
            state[13] = temp;

            // 第三行循环左移2个字节
            temp = state[2];
            state[2] = state[10];
            state[10] = temp;
            temp = state[6];
            state[6] = state[14];
            state[14] = temp;

            // 第四行循环左移3个字节
            temp = state[15];
            state[15] = state[11];
            state[11] = state[7];
            state[7] = state[3];
            state[3] = temp;
        }
        void MixColumns(block& state_) {
            auto s = state_.data();
            auto state = state_.get<u8>();
            for (int i = 0; i < 4; i++) {
                s[i * 4] = Multiply(0x02, state[i * 4]) ^ Multiply(0x03, state[i * 4 + 1])^ Multiply(0x01, state[i * 4 + 2])^ Multiply(0x01, state[i * 4 + 3]);
                s[i * 4 + 1] = Multiply(0x01, state[i * 4]) ^ Multiply(0x02, state[i * 4 + 1]) ^ Multiply(0x03, state[i * 4 + 2]) ^ Multiply(0x01, state[i * 4 + 3]);
                s[i * 4 + 2] = Multiply(0x01, state[i * 4]) ^ Multiply(0x01, state[i * 4 + 1]) ^ Multiply(0x02, state[i * 4 + 2]) ^ Multiply(0x03, state[i * 4 + 3]);
                s[i * 4 + 3] = Multiply(0x03, state[i * 4]) ^ Multiply(0x01, state[i * 4 + 1]) ^ Multiply(0x01, state[i * 4 + 2]) ^ Multiply(0x02, state[i * 4 + 3]);
            }
        }

        void AES::setKey(const block& userKey) {
            u8* RoundKey = (u8*)mRoundKeys.data();
            auto Key = userKey.data();

            std::array<u8, 4> temp = {};  // 中间变量，用于生成轮密钥

            // 第一个轮密钥即密钥本身
            for (int i = 0; i < 4; i++) {
                RoundKey[i * 4] = Key[i * 4];
                RoundKey[i * 4 + 1] = Key[i * 4 + 1];
                RoundKey[i * 4 + 2] = Key[i * 4 + 2];
                RoundKey[i * 4 + 3] = Key[i * 4 + 3];
            }

            for (int i = 4; i < 4 * (rounds + 1); i++) {
                // 首先提取出上一个字
                temp[0] = RoundKey[(i - 1) * 4];
                temp[1] = RoundKey[(i - 1) * 4 + 1];
                temp[2] = RoundKey[(i - 1) * 4 + 2];
                temp[3] = RoundKey[(i - 1) * 4 + 3];

                if (i % 4 == 0) {
                    // 先循环左移一个字节
                    auto tmp = temp[0];
                    temp[0] = temp[1];
                    temp[1] = temp[2];
                    temp[2] = temp[3];
                    temp[3] = tmp;
                    // 然后进行字节代替
                    temp[0] = getSBoxValue(temp[0]);
                    temp[1] = getSBoxValue(temp[1]);
                    temp[2] = getSBoxValue(temp[2]);
                    temp[3] = getSBoxValue(temp[3]);

                    // 最后与轮常量异或
                    temp[0] ^= Rcon[i / 4];
                }

                int j = 4 * i, k = 4 * (i - 4);
                RoundKey[j] = RoundKey[k] ^ temp[0];
                RoundKey[j + 1] = RoundKey[k + 1] ^ temp[1];
                RoundKey[j + 2] = RoundKey[k + 2] ^ temp[2];
                RoundKey[j + 3] = RoundKey[k + 3] ^ temp[3];
            }
        }

        block roundEnc(block& state, const block& roundKey) {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            state = state ^ roundKey;
            return state;
        }
        block finalEnc(block& state, const block& roundKey) {
            SubBytes(state);
            ShiftRows(state);
            state = state ^ roundKey;
            return state;
        }
        void AES::EncBlocks(const block& plaintext, block& ciphertext) {
            ciphertext = plaintext ^ mRoundKeys[0];
            for (int i = 1; i < 10; i++)
                ciphertext = roundEnc(ciphertext, mRoundKeys[i]);
            ciphertext = finalEnc(ciphertext, mRoundKeys[10]);
        }

        void InvSubBytes(block& state_) {
            auto state = state_.data();
            for (int i = 0; i < 16; i++)
                state[i] = getSBoxInvert(state[i]);
        }
        void InvShiftRows(block& state_) {
            auto state = state_.data();
            u8 temp;
            // 第一行不动
            // 第二行循环右移1个字节
            temp = state[13];
            state[13] = state[9];
            state[9] = state[5];
            state[5] = state[1];
            state[1] = temp;

            // 第三行循环右移2个字节
            temp = state[10];
            state[10] = state[2];
            state[2] = temp;
            temp = state[14];
            state[14] = state[6];
            state[6] = temp;

            // 第四行循环右移3个字节
            temp = state[3];
            state[3] = state[7];
            state[7] = state[11];
            state[11] = state[15];
            state[15] = temp;
        }
        void InvMixColumns(block& state_) {
            auto s = state_.data();
            auto state = state_.get<u8>();
            for (int i = 0; i < 4; i++) {
                s[i * 4] = Multiply(0x0e, state[i * 4]) ^ Multiply(0x0b, state[i * 4 + 1]) ^ Multiply(0x0d, state[i * 4 + 2]) ^ Multiply(0x09, state[i * 4 + 3]);
                s[i * 4 + 1] = Multiply(0x09, state[i * 4]) ^ Multiply(0x0e, state[i * 4 + 1]) ^ Multiply(0x0b, state[i * 4 + 2]) ^ Multiply(0x0d, state[i * 4 + 3]);
                s[i * 4 + 2] = Multiply(0x0d, state[i * 4]) ^ Multiply(0x09, state[i * 4 + 1]) ^ Multiply(0x0e, state[i * 4 + 2]) ^ Multiply(0x0b, state[i * 4 + 3]);
                s[i * 4 + 3] = Multiply(0x0b, state[i * 4]) ^ Multiply(0x0d, state[i * 4 + 1]) ^ Multiply(0x09, state[i * 4 + 2]) ^ Multiply(0x0e, state[i * 4 + 3]);
            }
        }

        block roundDec(block& state, const block& roundKey) {
            InvShiftRows(state);
            InvSubBytes(state);
            state = state ^ roundKey;
            InvMixColumns(state);
            return state;
        }
        block finalDec(block& state, const block& roundKey) {
            InvShiftRows(state);
            InvSubBytes(state);
            state = state ^ roundKey;
            return state;
        }
        void AES::DecBlocks(const block& ciphertext, block& plaintext) {
            plaintext = ciphertext ^ mRoundKeys[10];
            for (int i = 9; i > 0; i--)
                plaintext = roundDec(plaintext, mRoundKeys[i]);
            plaintext = finalDec(plaintext, mRoundKeys[0]);
        }

        void AES::cbcEncBlocks(const block* plaintext, u64 blockLength, const block& Iv, block* ciphertext) {
            EncBlocks(*plaintext ^ Iv, *ciphertext);  // 对第一个明文块进行加密
            for (int i = 1; i < blockLength; i++)
                EncBlocks(ciphertext[i - 1] ^ plaintext[i], ciphertext[i]);
        }
        void AES::ecbEncBlocks(const block* plaintext, u64 blockLength, block* ciphertext) {
            for (int i = 0; i < blockLength; i++)
                EncBlocks(plaintext[i], ciphertext[i]);
        }

        void AES::cbcDecBlocks(const block* ciphertext, u64 blockLength, const block& Iv, block* plaintext) {
            // 先解密出第一个明文块
            DecBlocks(*ciphertext, *plaintext);
            (*plaintext) ^= Iv;
            for (int i = 1; i < blockLength; i++) {
                DecBlocks(ciphertext[i], plaintext[i]);
                plaintext[i] ^= ciphertext[i - 1];
            }
        }
        void AES::ecbDecBlocks(const block* ciphertext, u64 blockLength, block* plaintext) {
            for (int i = 0; i < blockLength; i++)
                DecBlocks(ciphertext[i], plaintext[i]);
        }

        block* AES::Encrypt(std::string msg, EncMode mode, const std::initializer_list<const block>& Iv) {
            auto blockLength = msg.length() / 16 + 1;
            this->blockLength = blockLength;  // 存储块个数
            block* plaintext = toBlock(msg);  // 先对明文数据进行分组填充
            block* ciphertext = new block[blockLength];
            switch (mode) {
            case EncMode::ECB_MODE:
            {
                ecbEncBlocks(plaintext, blockLength, ciphertext);
                break;
            }
            case EncMode::CBC_MODE:
            {
                cbcEncBlocks(plaintext, blockLength, *Iv.begin(), ciphertext);
                break;
            }
            default:
                break;
            }
            return ciphertext;
        }
        std::string AES::Decrypt(block* ciphertext, EncMode mode, const std::initializer_list<const block>& Iv) {
            block* plaintext = new block[this->blockLength];
            switch (mode)
            {
            case EncMode::ECB_MODE:
            {
                ecbDecBlocks(ciphertext, this->blockLength, plaintext);
                break;
            }
            case EncMode::CBC_MODE:
            {
                cbcDecBlocks(ciphertext, this->blockLength, *Iv.begin(), plaintext);
                break;
            }
            default:
                break;
            }
            std::stringstream ss;
            // 先将其余分组写入字符流
            for (u64 i = 0; i < blockLength - 1; i++) {
                auto data = plaintext[i].data();
                ss.write((const char*)data, 16);
            }
            // 处理最后一个分组，检查填充
            auto num = plaintext[blockLength - 1].data()[15];  // 获取填充的长度
            for (size_t i = 15; i >= 16 - num; i--) {
                if (plaintext[blockLength - 1].data()[i] != num)
                    std::logic_error("The padding of the plaintext is wrong");
            }
            ss.write((const char*)plaintext[blockLength - 1].data(), 16 - num);
            return ss.str();
        }
	}
}
