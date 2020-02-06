/*
*  Copyright 2020 Ivan Ryabov
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
/*******************************************************************************
 * apsio Unit Test Suit
 *	@file test/test_auth.cpp
 *	@brief		Test suit for apsio::Auth
 ******************************************************************************/
#include <apsio/auth.hpp>    // Class being tested.

#include <gtest/gtest.h>

using namespace Solace;
using namespace apsio::Auth;


TEST(AuthMatch, matchExact) {
	auto m = Match{"user", "resource"};
	// Match username and resource exactly
	EXPECT_TRUE(m.matches(m));

	// Does not match any other user name or resource name
	EXPECT_FALSE(m.matches({"user-x", "resource"}));
	EXPECT_FALSE(m.matches({"user", "other-resource"}));
	EXPECT_FALSE(m.matches({"user-x", "other-resource"}));
}


TEST(AuthMatch, matchWildcardUsername) {
	auto anyUser = Match{"*", "resource"};
	// Wildcard matches itself
	EXPECT_TRUE(anyUser.matches(anyUser));

	// Wildcard matches any user name
	EXPECT_TRUE(anyUser.matches({"user", "resource"}));
	EXPECT_TRUE(anyUser.matches({"user-x", "resource"}));
	// Wildcard DOES NOT maatch other resources
	EXPECT_FALSE(anyUser.matches({"user", "resource-xyz"}));
}


TEST(AuthMatch, matchWildcardResource) {
	auto anyResource = Match{"user-x", "*"};
	// Wildcard matches itself
	EXPECT_TRUE(anyResource.matches(anyResource));

	// Wildcard matches any user name
	EXPECT_TRUE(anyResource.matches({"user-x", "resource-12"}));
	EXPECT_TRUE(anyResource.matches({"user-x", "resource"}));
	// Wildcard DOES NOT maatch other users
	EXPECT_FALSE(anyResource.matches({"user", "resource"}));
}


TEST(AuthMatch, matchWildcardAny) {
	auto any = Match{"*", "*"};
	// Wildcard matches itself
	EXPECT_TRUE(any.matches(any));

	// Wildcard matches any user name
	EXPECT_TRUE(any.matches({"user-x", "resource-12"}));
	EXPECT_TRUE(any.matches({"user-x", "resource"}));
	EXPECT_TRUE(any.matches({"user", "resource"}));
}
