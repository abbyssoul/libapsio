/*
*  Copyright (C) Ivan Ryabov - All Rights Reserved
*
*  Unauthorized copying of this file, via any medium is strictly prohibited.
*  Proprietary and confidential.
*
*  Written by Ivan Ryabov <abbyssoul@gmail.com>
*/


#include "apsio/server.hpp"

#include "asyncServerSession.hpp"
#include "asyncConnectionListener.hpp"

using namespace Solace;
using namespace kasofs;
using namespace styxe;
using namespace apsio;


Observer::~Observer() = default;

Session::~Session() = default;

Server::ConnectionListener::~ConnectionListener() = default;


static_assert(std::is_move_assignable_v<Server::Config>);
static_assert(std::is_move_constructible_v<Server::Config>);


apsio::Result<std::shared_ptr<Server::ConnectionListener>>
Server::listen(styxe::DialString endpoint, Config&& config, Observer& sessionObserver) {
	auto maybeServer = createServer(endpoint.protocol, *this, sessionObserver, mv(config));
	if (!maybeServer) {
		return maybeServer.moveError();
	}

	auto started = (*maybeServer)->listen(endpoint);
	if (!started) {
		return started.moveError();
	}

	return maybeServer;
}
