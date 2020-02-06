/*
*  Copyright (C) Ivan Ryabov - All Rights Reserved
*
*  Unauthorized copying of this file, via any medium is strictly prohibited.
*  Proprietary and confidential.
*
*  Written by Ivan Ryabov <abbyssoul@gmail.com>
*/
#pragma once
#ifndef APSIO_AUTHFILE_HPP
#define APSIO_AUTHFILE_HPP

#include "apsio/server.hpp"

#include <solace/memoryResource.hpp>

namespace apsio {

namespace impl {

/// Authentication strategy for a particular auth request+user+resource
struct AuthFile {
	using size_type = Solace::MemoryView::size_type;

	AuthFile(Solace::StringView uname, Solace::StringView resource, Auth::Strategy& strategy);

	Result<kasofs::User>
	authenticate(Solace::StringView uname, Solace::StringView resource);

	Result<size_type>
	write(Solace::MemoryView data, Solace::uint64 offset);

	bool isAuthRequired() const noexcept { return strategy.get().isRequired; }

protected:

	Auth::Match			acl;

	// Weak pointer!
	std::reference_wrapper<Auth::Strategy>	strategy;

	Solace::MemoryResource authBuffer;
};


static_assert(std::is_move_constructible_v<AuthFile>);
static_assert(std::is_move_assignable_v<AuthFile>);


}  // namespace impl
}  // namespace apsio
#endif  // APSIO_AUTHFILE_HPP
