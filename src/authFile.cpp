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
#include "authFile.hpp"


using namespace Solace;
using namespace apsio;
using namespace apsio::impl;


AuthFile::AuthFile(String user, Optional<uint32> uid, String resource, Auth::Strategy& auth)
	: _uname{mv(user)}
	, _resource{mv(resource)}
	, _uid{mv(uid)}
	, _strategy{auth}
	, _authBuffer{}
{

}


apsio::Result<AuthFile::size_type>
AuthFile::write(MemoryView data, uint64 offset) {
	auto view = _authBuffer.view();
	auto writeResult = view.write(data, offset);
	if (!writeResult)
		return writeResult.moveError();

	return 0;
}


apsio::Result<kasofs::User>
AuthFile::authenticate(StringView uname, Optional<uint32> uid, StringView resource) {
	// Check username and resource the same as what this file been created for.
	Auth::Match acl{_uname.view(), _resource.view()};
	if (!acl.matches({uname, resource}) || _uid != uid) {
		return makeError(GenericError::ACCES, "authenticate");
	}

	// Delegate authentication to the strategy
	return _strategy.get().authenticate(uname, uid, resource, _authBuffer.view());
}
