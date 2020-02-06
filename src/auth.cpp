/*
*  Copyright (C) Ivan Ryabov - All Rights Reserved
*
*  Unauthorized copying of this file, via any medium is strictly prohibited.
*  Proprietary and confidential.
*
*  Written by Ivan Ryabov <abbyssoul@gmail.com>
*/

#include "apsio/auth.hpp"

#include <algorithm>
#include <string.h>
#include <pwd.h>


using namespace Solace;
using namespace apsio;


const StringLiteral kWildcardMatch{"*"};
static Auth::Strategy kDenyAll;


Auth::Strategy::~Strategy() = default;


namespace  {

Optional<kasofs::User>
lookup(StringView uname) {
	char uNameBuffer[256];
	strncpy(uNameBuffer, uname.data(), std::min<size_t>(sizeof(uNameBuffer), uname.size()));

	passwd const* pass = getpwnam(uNameBuffer);
	if (!pass) {
		return none;
	}

	return kasofs::User{pass->pw_uid, pass->pw_gid};
}

}  // namespace


bool
Auth::Match::matches(Match other) const noexcept {
	bool const matchesResource = resource.equals(kWildcardMatch) || other.resource == resource;
	bool const matchesUser = uname.equals(kWildcardMatch) || other.uname == uname;

	return matchesUser && matchesResource;
}


apsio::Result<kasofs::User>
Auth::Strategy::authenticate(StringView uname, StringView SOLACE_UNUSED(resource), MemoryView SOLACE_UNUSED(data)) {
	auto maybeUser = lookup(uname);
	if (!maybeUser) {
		return makeError(GenericError::PERM, "auth");
	}

	// TODO: Establish auth FID for aname

	return Ok(*maybeUser);
}


Auth::Strategy&
Auth::Policy::findAuthStrategyFor(Match userReq) const noexcept {
	auto b = std::begin(_authPolicies);
	auto e = std::end(_authPolicies);

	auto const size = _authPolicies.size();
	if (b == e)
		return kDenyAll;

	auto it = std::find_if(b, e, [userReq](Auth::Policy::ACL const& acl) {
		return acl.match.matches(userReq);
	});

	if (it == e) {
		return kDenyAll;
	}

	return *(it->strategy.get());
}

