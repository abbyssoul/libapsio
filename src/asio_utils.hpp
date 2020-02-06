#ifndef ASIO_UTILS_HPP
#define ASIO_UTILS_HPP

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

#endif // ASIO_UTILS_HPP
