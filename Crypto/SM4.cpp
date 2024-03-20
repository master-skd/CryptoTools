#include "SM4.h"

namespace skd {
	namespace Crypto {
        static const u8 sBox[256] = {
            0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
            0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
            0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
            0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
            0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
            0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
            0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
            0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
            0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
            0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
            0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
            0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
            0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
            0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
            0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
            0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
        };

        static const u32 MK[4] = { 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC };

        static const u32 CK[32] = { 
            0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
            0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
            0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
            0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
            0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
            0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
            0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
            0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
        };

        inline u8 getSBoxValue(u32 num) { return sBox[num]; }

        inline u32 ShiftLeft(u32 x, int n) {  // 循环左移n位
            return (x << n) | (x >> (32 - n));
        }
        inline u32 ShiftRight(u32 x, int n) {  // 循环右移n位
            return (x >> n) | (x << (32 - n));
        }

        void SubBytes(u32* x) {  // 对一个字进行字节代替
            u8* b = (u8*)x;
            for (int i = 0; i < 4; i++)
                *(b + i) = getSBoxValue(*(b + i));
        }

        u32 T(u32 c) {  // 合成置换
            SubBytes(&c);
            return c ^ ShiftLeft(c, 2) ^ ShiftLeft(c, 10) ^ ShiftLeft(c, 18) ^ ShiftLeft(c, 24);
        }

        u32 T_pie(u32 x) {  // 密钥扩展所用置换
            SubBytes(&x);
            return x ^ ShiftLeft(x, 13) ^ ShiftLeft(x, 23);
        }

        u32 F(u32 x0, u32 x1, u32 x2, u32 x3, u32 roundKey) {  // 轮函数
            return x0 ^ T(x1 ^ x2 ^ x3 ^ roundKey);
        }

		SM4::SM4(const block& userKey) {
            setKey(userKey);
		}

        void SM4::setKey(const block& userKey) {
            auto initWords = userKey.get<u32>();
            std::array<u32, 36> K = {};
            for (int i = 0; i < 4; i++)
                K[i] = initWords[i] ^ MK[i];
            for (int i = 0; i < 32; i++) {
                K[i + 4] = K[i] ^ T_pie(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]);
                mRoundKeys[i] = K[i + 4];
            }
        }

        void SM4::EncBlocks(const block& plaintext, block& ciphertext) {
            auto initWords = plaintext.get<u32>();  // 首先将明文转成4个字
            std::array<u32, 36> X = {initWords[0], initWords[1], initWords[2], initWords[3]};
            for (int i = 0; i < 32; i++) {  // 迭代32轮
                X[i + 4] = F(X[i], X[i + 1], X[i + 2], X[i + 3], mRoundKeys[i]);
            }
            std::array<u32, 4> a = { X[32], X[33], X[34], X[35] };
            ciphertext = block(a);
        }

        void SM4::DecBlocks(const block& ciphertext, block& plaintext) {
            auto initWords = ciphertext.get<u32>();  // 首先将密文转成4个字
            std::array<u32, 36> X = { initWords[0], initWords[1], initWords[2], initWords[3] };
            for (int i = 0; i < 32; i++) {  // 迭代32轮
                X[i + 4] = F(X[i], X[i + 1], X[i + 2], X[i + 3], mRoundKeys[31 - i]);
            }
            std::array<u32, 4> a = { X[32], X[33], X[34], X[35] };
            plaintext = block(a);
        }

        void SM4::cbcEncBlocks(const block* plaintext, u64 blockLength, const block& Iv, block* ciphertext) {
            EncBlocks(*plaintext ^ Iv, *ciphertext);  // 对第一个明文块进行加密
            for (int i = 1; i < blockLength; i++)
                EncBlocks(ciphertext[i - 1] ^ plaintext[i], ciphertext[i]);
        }
        void SM4::ecbEncBlocks(const block* plaintext, u64 blockLength, block* ciphertext) {
            for (int i = 0; i < blockLength; i++)
                EncBlocks(plaintext[i], ciphertext[i]);
        }

        void SM4::cbcDecBlocks(const block* ciphertext, u64 blockLength, const block& Iv, block* plaintext) {
            // 先解密出第一个明文块
            DecBlocks(*ciphertext, *plaintext);
            (*plaintext) ^= Iv;
            for (int i = 1; i < blockLength; i++) {
                DecBlocks(ciphertext[i], plaintext[i]);
                plaintext[i] ^= ciphertext[i - 1];
            }
        }
        void SM4::ecbDecBlocks(const block* ciphertext, u64 blockLength, block* plaintext) {
            for (int i = 0; i < blockLength; i++)
                DecBlocks(ciphertext[i], plaintext[i]);
        }

        block* SM4::Encrypt(std::string msg, EncMode mode, const std::initializer_list<const block>& Iv) {
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
        std::string SM4::Decrypt(block* ciphertext, EncMode mode, const std::initializer_list<const block>& Iv) {
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
