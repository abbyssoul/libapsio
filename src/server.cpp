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
#include "apsio/server.hpp"

#include "asyncServerSession.hpp"
#include "asyncConnectionListener.hpp"

using namespace Solace;
using namespace apsio;


Observer::~Observer() = default;

Session::~Session() = default;

Server::ConnectionListener::~ConnectionListener() = default;


static_assert(std::is_move_assignable_v<Server::Config>);
static_assert(std::is_move_constructible_v<Server::Config>);


apsio::Result<std::shared_ptr<Server::ConnectionListener>>
Server::listen(DialString endpoint, Config&& config, Observer& sessionObserver) {
	auto maybeServer = createServer(endpoint.protocol, *this, sessionObserver, mv(config));
	if (!maybeServer) {
		return maybeServer.moveError();
	}

	auto started = (*maybeServer)->listen(endpoint);
	if (!started) {
		return started.moveError();
	}

	return apsio::Result<std::shared_ptr<Server::ConnectionListener>>{types::okTag, maybeServer.moveResult()};
}
