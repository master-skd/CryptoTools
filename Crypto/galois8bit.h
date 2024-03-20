#pragma once
#include "../Common/Defines.h"
#define POLYNOMIAL (1 << 4) | (1 << 3) | (1 << 1) | 1

u8 GaloisValue[1 << 8];  // ��������Ԫ�洢����Ԫ��
u8 GaloisIndex[1 << 8];  // ÿ��Ԫ�ض�Ӧ�ı�ԭԪ��ָ��

namespace skd {
	namespace Crypto {
		void galois8Init() {  // ��������Ԫ����ÿ��Ԫ�ض�Ӧ������
			int i, j = 1;
			for (i = 0; i < 255; i++) {
				GaloisValue[i] = j;
				GaloisIndex[GaloisValue[i]] = i;
				if (j & 0x80) {
					j <<= 1;
					j ^= POLYNOMIAL;
				}
				else
					j <<= 1;
			}
		}

		inline u8 galoisAdd(u8 x, u8 y) {  // ٤�޻����мӷ�
			return x ^ y;
		}

		inline u8 galoisSub(u8 x, u8 y) {  // ٤�޻����м���
			return x ^ y;
		}

		inline u8 xtime(u8 x) {  // ٤�޻�����2 * x
			return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
		}

		inline u8 galoisMul(u8 x, u8 y) {  // ٤�޻����г˷�
			if (!x || !y)
				return 0;
			u8 p = 0;
			for (int i = 0; i < 8; i++) {
				if (x & 1)
					p ^= y;
				y = xtime(y);
				x >>= 1;
			}
			return p;
		}

		inline u8 galoisDiv(u8 x, u8 y) {  // ٤�޻����г���
			if (!x || !y)
				return 0;
			return galoisMul(x, galoisInv(y));
		}

		inline u8 galoisPow(u8 x, u8 p) {  // ٤�޻������ݴ�
			if (!x)
				return 0;
			if (!p)
				return 1;
			u8 re = 1;
			while (p != 0) {
				if (p & 1) {
					re = galoisMul(re, x);
				}
				p >>= 1;
				x = galoisMul(x, x);
			}
			return re;
		}

		inline u8 galoisInv(u8 x) {  // ٤�޻���������
			if (!x)
				return 0;
			u8 j = GaloisIndex[x];
			return GaloisValue[(255 - j) % 255];
		}
	}
}
