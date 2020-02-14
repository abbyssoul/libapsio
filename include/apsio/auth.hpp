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
#ifndef APSIO_AUTH_HPP
#define APSIO_AUTH_HPP

#include "types.hpp"

#include <kasofs/kasofs.hpp>

#include <solace/array.hpp>


namespace apsio {

namespace Auth {

/// Aux structure to represent ACL entry: who can access what
struct Match {
	Solace::StringView uname{};		/// Who has access to a resource.
	Solace::StringView resource{};  /// What resource access is required to.

	bool matches(Match other) const noexcept;
};

static_assert(std::is_move_constructible_v<Match>);
static_assert(std::is_move_assignable_v<Match>);

/**
 * Pluggable Authentication strategy
 */
struct Strategy {

	virtual ~Strategy();

	/// Does this strategy require exchange of messages
	bool isRequired{true};

	/**
	 * Attempt to authenticate a user given user name, resource and opaque auth-strategy specific data
	 * @param uname User name to authenticate
	 * @param uid Optional User ID to authenticate as.
	 * @param resource Resource access required to.
	 * @param data Authentication mechanism specific data.
	 * @return Authentiocation result: A user object or an error.
	 */
	Result<kasofs::User>
	virtual authenticate(Solace::StringView uname,
						 Solace::Optional<Solace::uint32> uid,
						 Solace::StringView resource,
						 Solace::MemoryView data);
};


/**
 * Configured authentication policy.
 * If defines authenication method to be used for eash resource/user combination.
 */
struct Policy {
	struct ACL {
		Match						match{};
		std::unique_ptr<Strategy>	strategy{};
	};

	Policy() noexcept
	{}

	Policy(Solace::Array<ACL>&& policies) noexcept
		: _authPolicies{Solace::mv(policies)}
	{}

	/**
	 * Select authentication strategy for a given user / resource combination.
	 * @param match User name to be used for authentication
	 * @return A strategy to be used for authentication.
	 */
	Strategy& findAuthStrategyFor(Match match) const noexcept;

protected:

	Solace::Array<ACL>	_authPolicies{};
};

static_assert(std::is_move_constructible_v<Policy>);
static_assert(std::is_move_assignable_v<Policy>);

}  // namespace Auth
}  // end of namespace apsio
#endif  // APSIO_AUTH_HPP
