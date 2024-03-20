#pragma once
#include "../Common/Defines.h"
#include "galois8bit.h"
#include<assert.h>
#define MAX 64

namespace skd {
	namespace Crypto {
		typedef struct Matrix {
			int m_row;
			int m_col;
			u8 m_data[MAX][MAX];
		} matrix_t;

		matrix_t matrixAdd(const matrix_t& A, const matrix_t& B) {
			// 首先判断两个矩阵的行和列是否相同
			assert(A.m_col == B.m_col);
			assert(A.m_row == B.m_row);

			matrix_t res;
			res.m_col = A.m_col, res.m_row = A.m_row;
			for (int i = 0; i < res.m_row; i++) {
				for (int j = 0; j < res.m_col; j++) {
					res.m_data[i][j] = galoisAdd(A.m_data[i][j], B.m_data[i][j]);
				}
			}
			return res;
		}

		matrix_t matrixSub(const matrix_t& A, const matrix_t& B) {
			// 首先判断两个矩阵的行和列是否相同
			assert(A.m_col == B.m_col);
			assert(A.m_row == B.m_row);

			matrix_t res;
			res.m_col = A.m_col, res.m_row = A.m_row;
			for (int i = 0; i < res.m_row; i++) {
				for (int j = 0; j < res.m_col; j++) {
					res.m_data[i][j] = galoisSub(A.m_data[i][j], B.m_data[i][j]);
				}
			}
			return res;
		}

		matrix_t matrixMul(const matrix_t& A, const matrix_t& B) {
			// 首先判断两个矩阵能否相乘
			assert(A.m_col == B.m_row);

			matrix_t res;
			res.m_row = A.m_row, res.m_col = B.m_col;
			for (int i = 0; i < res.m_row; i++) {
				for (int j = 0; j < res.m_col; j++) {
					u8 sum = 0;
					for (int k = 0; k < A.m_col; k++) {
						auto temp = galoisMul(A.m_data[i][k], B.m_data[k][j]);
						sum = galoisAdd(sum, temp);
					}
					res.m_data[i][j] = sum;
				}
			}
			return res;
		}

		matrix_t matrixNumMul(matrix_t A, u8 k) {
			matrix_t res;
			res.m_row = A.m_row, res.m_col = A.m_col;
			while (k != 0) {
				if (k & 1) {
					res = matrixAdd(res, A);
				}
				k >>= 1;
				A = matrixAdd(A, A);
			}
			return res;
		}
	}
}
