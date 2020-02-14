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
