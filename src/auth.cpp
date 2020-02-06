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
	char pwdBuffer[256];
	strncpy(uNameBuffer, uname.data(), std::min<size_t>(sizeof(uNameBuffer), uname.size()));

	passwd pass;
	passwd* result;
	if (getpwnam_r(uNameBuffer, &pass, pwdBuffer, sizeof (pwdBuffer), &result) != 0)
		return none;  // Error retrieving record. Probably buffer too small :(

	if (result != &pass)
		return none;  // Could not find an entry

	return kasofs::User{result->pw_uid, result->pw_gid};
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

	// TODO(abbyssoul): Establish auth FID for aname

	return Ok(*maybeUser);
}


Auth::Strategy&
Auth::Policy::findAuthStrategyFor(Match userReq) const noexcept {
	auto it = std::find_if(std::begin(_authPolicies), std::end(_authPolicies), [userReq](Auth::Policy::ACL const& acl) {
		return acl.match.matches(userReq);
	});

	if (it == std::end(_authPolicies)) {
		return kDenyAll;
	}

	return *(it->strategy.get());
}

