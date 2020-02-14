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

	auto unameSize = std::min<size_t>(sizeof(uNameBuffer) - 1, uname.size());
	strncpy(uNameBuffer, uname.data(), unameSize);
	uNameBuffer[unameSize] = 0;

	passwd pass;
	passwd* result;
	if (getpwnam_r(uNameBuffer, &pass, pwdBuffer, sizeof(pwdBuffer), &result) != 0)
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
Auth::Strategy::authenticate(StringView uname, Optional<uint32> uid, StringView, MemoryView) {
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

