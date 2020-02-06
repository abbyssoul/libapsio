/*
*  Copyright (C) Ivan Ryabov - All Rights Reserved
*
*  Unauthorized copying of this file, via any medium is strictly prohibited.
*  Proprietary and confidential.
*
*  Written by Ivan Ryabov <abbyssoul@gmail.com>
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
	 * @param resource Resource access required to.
	 * @param data Authentication mechanism specific data.
	 * @return Authentiocation result: A user object or an error.
	 */
	Result<kasofs::User>
	virtual authenticate(Solace::StringView uname, Solace::StringView resource, Solace::MemoryView data);
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
