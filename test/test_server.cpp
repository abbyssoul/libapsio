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
 *	@file test/test_server.cpp
 *	@brief		Test suit for apsio::Server
 ******************************************************************************/
#include <apsio/simpleServer.hpp>    // Class being tested.

#include "asio_utils.hpp"
#include <filesystem>  // temp_directory_path

#include <gtest/gtest.h>

using namespace Solace;
using namespace apsio;


namespace /*anonymous*/ {

struct TestServer: public ::testing::Test {

	void SetUp() override {
		_baseMem = _memManager.size();
	}

	void TearDown() override {
		EXPECT_EQ(_baseMem, _memManager.size());
	}

protected:
	asio::io_context	_iocontext;
	kasofs::User		_owner{0, 0};
	kasofs::Vfs			_vfs{_owner, kasofs::FilePermissions{0666}};

	MemoryManager&		_memManager = getSystemHeapMemoryManager();

	MemoryManager::size_type _baseMem;
};

}  // anonymous namespace



TEST_F(TestServer, listeningOnNoAddressFails) {
	auto server = SimpleServer{_iocontext, _vfs, _memManager};

	Server::Config config;

	styxe::DialString invalidEndpoint;
	auto maybeListeners = server.listen(invalidEndpoint, mv(config));
	EXPECT_TRUE(maybeListeners.isError());
}


TEST_F(TestServer, callingListenMoreThenOnceIsOk) {
	auto server = SimpleServer{_iocontext, _vfs, _memManager};

	std::string strPath{"unix:"};
	strPath += (std::filesystem::temp_directory_path() / "apsio.test");

	auto maybeLocal = styxe::tryParseDailString(StringView(strPath.data(), strPath.size()));
	ASSERT_TRUE(maybeLocal.isOk());

	auto maybeListeners1 = server.listen(*maybeLocal, Server::Config{});
	EXPECT_TRUE(maybeListeners1.isOk());

	auto maybeRemote = styxe::tryParseDailString("tcp:0.0.0.0:53535");
	ASSERT_TRUE(maybeRemote.isOk());

	auto maybeListeners2 = server.listen(*maybeRemote, Server::Config{});
	EXPECT_TRUE(maybeListeners2.isOk());
}


TEST_F(TestServer, emptyAuthPolicyDenyAll) {
	auto server = SimpleServer{_iocontext, _vfs, _memManager};

	std::string strPath{"unix:"};
	strPath += (std::filesystem::temp_directory_path() / "apsio.test");
	auto maybeLocal = styxe::tryParseDailString(StringView(strPath.data(), strPath.size()));
	ASSERT_TRUE(maybeLocal.isOk());

	Server::Config config;

	auto maybeListener = server.listen(*maybeLocal, Server::Config{});
	EXPECT_TRUE(maybeListener.isOk());

	auto& listener = *maybeListener;

	auto& policy = listener->authPolicy()->findAuthStrategyFor({"user", "somewhere"});
	EXPECT_TRUE(policy.isRequired);
	EXPECT_TRUE(policy.authenticate("user", none, "somewhere", MemoryView{}).isError());
}
