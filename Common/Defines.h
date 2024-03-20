#pragma once
#include "Block.h"
#include<memory>

namespace skd {
	namespace Crypto {
		template<typename T> using ptr = T*;
		template<typename T> using uptr = std::unique_ptr<T>;
		template<typename T> using sptr = std::shared_ptr<T>;

		typedef uint64_t u64;
		typedef int64_t i64;
		typedef uint32_t u32;
		typedef int32_t i32;
		typedef uint16_t u16;
		typedef int16_t i16;
		typedef uint8_t u8;
		typedef int8_t i8;

		enum class EncMode {  // 分组密码工作模式
			ECB_MODE,
			CBC_MODE
		};
	}
}
