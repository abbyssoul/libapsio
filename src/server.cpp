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

#include <dialstring/ostream.hpp>
#include <solace/output_utils.hpp>
#include <iostream>

using namespace Solace;
using namespace kasofs;
using namespace styxe;
using namespace apsio;


Session::~Session() = default;
Observer::~Observer() = default;

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
//		std::cerr << "Error Server::listen('" << endpoint << "'): " << started.getError() << std::endl;
		return started.moveError();
	}

	return maybeServer;
}


void
SimpleServer::onSessionAccepted(styxe::DialString endpoint, std::shared_ptr<Session> session) {
	std::cerr << "New session on ('" << endpoint << "'): " << std::endl;
	_sessions.emplace_back(mv(session));
}

void
SimpleServer::onAcceptFailed(styxe::DialString endpoint, Error error) {
	std::cerr << "Error Server::listen('" << endpoint << "'): " << error << std::endl;
	//std::cerr << "Async server accept failed: " << ec.message() << ". No more connections accepted\n";
}

void
SimpleServer::onSessionTerminated(Session* session) {
	auto const sessionCount = _sessions.size();
	std::clog << ">>> Server session closed [" << sessionCount;
	_sessions.erase(
				std::remove_if(_sessions.begin(), _sessions.end(), [session](auto const& n) { return (session == n.get()); }),
				_sessions.end());
	std::clog << " -> " << _sessions.size() << "]\n";
}
