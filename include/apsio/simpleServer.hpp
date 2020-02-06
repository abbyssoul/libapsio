/*
*  Copyright (C) Ivan Ryabov - All Rights Reserved
*
*  Unauthorized copying of this file, via any medium is strictly prohibited.
*  Proprietary and confidential.
*
*  Written by Ivan Ryabov <abbyssoul@gmail.com>
*/
#pragma once
#ifndef APSIO_SIMPLESERVER_HPP
#define APSIO_SIMPLESERVER_HPP

#include "server.hpp"

namespace apsio {

/**
 * Simple version of a 9p server intended for testing.
 * SimpleSever is observer of session lifecycle event and stores all new sessions.
 */
struct SimpleServer final :
		public Server,
		public Observer
{

	SimpleServer(asio::io_context& iocontext,
				 kasofs::Vfs& vfs,
				 Solace::MemoryManager& memManager = Solace::getSystemHeapMemoryManager()) noexcept
		: Server{iocontext, vfs, memManager}
	{}


	// Connection listeners signals:
	void onError(styxe::DialString endpoint, Error error) override;

	void onSessionAccepted(styxe::DialString endpoint, std::shared_ptr<Session> newSession) override;
	void onSessionTerminated(std::shared_ptr<Session> session) override;


	/**
	 * Begin listening for incomming connections using given configuration
	 * @param endpoint Endpoint to listen on for connections.
	 * @param config Options for listening
	 * @return A new state of the server
	 */
	Result<std::shared_ptr<ConnectionListener>>
	listen(styxe::DialString endpoint, Config&& config) {
		return Server::listen(endpoint, Solace::mv(config), *this);
	}

private:
	std::vector<std::shared_ptr<Session>> _sessions;
};

}  // end of namespace apsio
#endif  // APSIO_SIMPLESERVER_HPP
