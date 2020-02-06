/*
*  Copyright (C) Ivan Ryabov - All Rights Reserved
*
*  Unauthorized copying of this file, via any medium is strictly prohibited.
*  Proprietary and confidential.
*
*  Written by Ivan Ryabov <abbyssoul@gmail.com>
*/


#include "apsio/simpleServer.hpp"

// Output formatting
#include <dialstring/ostream.hpp>
#include <solace/output_utils.hpp>
#include <iostream>
#include <algorithm>

using namespace Solace;
using namespace kasofs;
using namespace styxe;
using namespace apsio;



void
SimpleServer::onError(styxe::DialString endpoint, Error error) {
	std::cerr << "Error Server::listen('" << endpoint << "'): " << error << std::endl;
}


void
SimpleServer::onSessionAccepted(styxe::DialString endpoint, std::shared_ptr<Session> session) {
	std::cerr << "New session on ('" << endpoint << "'): " << std::endl;
	_sessions.emplace_back(mv(session));
}


void
SimpleServer::onSessionTerminated(std::shared_ptr<Session> session) {
	auto const sessionCount = _sessions.size();
	std::clog << ">>> Server session closed [" << sessionCount;
	_sessions.erase(
				std::remove(_sessions.begin(), _sessions.end(), session),
				_sessions.end());
	std::clog << " -> " << _sessions.size() << "]\n";
}
