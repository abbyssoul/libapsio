/*
*  Copyright (C) Ivan Ryabov - All Rights Reserved
*
*  Unauthorized copying of this file, via any medium is strictly prohibited.
*  Proprietary and confidential.
*
*  Written by Ivan Ryabov <abbyssoul@gmail.com>
*/

#include "authFile.hpp"


using namespace Solace;
using namespace apsio;
using namespace apsio::impl;


AuthFile::AuthFile(StringView user, StringView resource, Auth::Strategy& auth)
	: acl{user, resource}
	, strategy{auth}
//	, authBuffer
{}


apsio::Result<AuthFile::size_type>
AuthFile::write(MemoryView data, uint64 offset) {
	auto view = authBuffer.view();
	auto writeResult = view.write(data, offset);
	if (!writeResult)
		return writeResult.moveError();

	return 0;
}


apsio::Result<kasofs::User>
AuthFile::authenticate(StringView uname, StringView resource) {
	// Check username and resource the same as what this file been created for.
	if (!acl.matches({uname, resource}))
		return makeError(GenericError::ACCES, "authenticate");

	// Delegate authentication to the strategy
	return strategy.get().authenticate(uname, resource, authBuffer.view());
}
