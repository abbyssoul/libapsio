/*
*  Copyright (C) Ivan Ryabov - All Rights Reserved
*
*  Unauthorized copying of this file, via any medium is strictly prohibited.
*  Proprietary and confidential.
*
*  Written by Ivan Ryabov <abbyssoul@gmail.com>
*/
#ifndef SRC_ASIO_UTILS_HPP_
#define SRC_ASIO_UTILS_HPP_

#include <solace/memoryResource.hpp>

#include "systemErrorDomain.hpp"

#include <asio/error_code.hpp>
#include <asio/buffer.hpp>

#include <string_view>


inline
auto asio_buffer(Solace::MemoryView view) noexcept {
	return asio::buffer(view.dataAddress(), view.size());
}

inline
auto asio_buffer(Solace::MutableMemoryView view) noexcept {
	return asio::buffer(view.dataAddress(), view.size());
}

inline
std::string_view as_string(Solace::StringView str) noexcept {
	return std::string_view{str.data(), str.size()};
}

inline
auto
fromAsioError(asio::error_code const& ec) noexcept {
	return apsio::impl::makeSystemError(ec);
}

#endif  // SRC_ASIO_UTILS_HPP_
