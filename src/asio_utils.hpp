/*
*  Copyright (C) 2020 Ivan Ryabov
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
*/
#pragma once
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
