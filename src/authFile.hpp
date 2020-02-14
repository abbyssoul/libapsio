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
#ifndef APSIO_AUTHFILE_HPP
#define APSIO_AUTHFILE_HPP

#include "apsio/server.hpp"

#include <solace/memoryResource.hpp>

namespace apsio {

namespace impl {

/// Authentication strategy for a particular auth request+user+resource
struct AuthFile {
	using size_type = Solace::MemoryView::size_type;

	AuthFile(Solace::String uname,
			 Solace::Optional<Solace::uint32> uid,
			 Solace::String resource,
			 Auth::Strategy& strategy);

	Result<kasofs::User>
	authenticate(Solace::StringView uname, Solace::Optional<Solace::uint32> uid, Solace::StringView resource);

	Result<size_type>
	write(Solace::MemoryView data, Solace::uint64 offset);

	bool isAuthRequired() const noexcept { return _strategy.get().isRequired; }

protected:

	Solace::String						_uname;
	Solace::String						_resource;
	Solace::Optional<Solace::uint32>	_uid;

	// Weak pointer!
	std::reference_wrapper<Auth::Strategy>	_strategy;

	Solace::MemoryResource _authBuffer;
};


static_assert(std::is_move_constructible_v<AuthFile>);
static_assert(std::is_move_assignable_v<AuthFile>);


}  // namespace impl
}  // namespace apsio
#endif  // APSIO_AUTHFILE_HPP
