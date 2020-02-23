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
#pragma once
#ifndef APSIO_SERVER_HPP
#define APSIO_SERVER_HPP

#include "types.hpp"
#include "auth.hpp"

#include <kasofs/kasofs.hpp>
#include <solace/dialstring.hpp>
#include <solace/posixErrorDomain.hpp>

#include <asio/io_context.hpp>


namespace apsio {

struct Server;

/**
 * Active session esteblished and managed by the server.
 */
struct Session {
	virtual ~Session();

	Session(Server& server, std::shared_ptr<Auth::Policy> authPolicy, struct Observer& observer) noexcept
		: _server{server}
		, _authPolicy{Solace::mv(authPolicy)}
		, _observer{observer}
	{
	}

	Server&	server() noexcept { return _server; }

	Observer& observer() noexcept { return _observer; }

	std::shared_ptr<Auth::Policy> authPolicy() noexcept { return _authPolicy; }

	virtual Result<void> terminate() = 0;

protected:
	Server&							_server;
	/// Authentication policy to be user for this session
	std::shared_ptr<Auth::Policy>	_authPolicy;
	/// Observer of sessions
	struct Observer&				_observer;
};


/**
 * Session stream observer interface.
 * Lifetime note: It is users responsibility to make sure that instance of the observer
 * passed to server lives at least as long as the server
 */
struct Observer {
	virtual ~Observer();

	/**
	 * Event handler: A new session has been created by a listener.
	 * Is expected that observe will store this session as it will be destroyed otherwise.
	 * @param listenerInterface Dialstring passed to the listener to identify listener interface.
	 * @param newSession An newly created session.
	 */
	virtual void onSessionAccepted(Solace::DialString listenerInterface, std::shared_ptr<Session> newSession) = 0;

	/**
	 * Event hadler: An error occured when attempting to accept a new session.
	 * @param listenerInterface Dialstring passed to the listener to identify listener interface.
	 * @param error Error details.
	 */
	virtual void onError(Solace::DialString listenerInterface, Error error) = 0;

	/**
	 * Terminate has been called on a session object and no read operations will be scheduler for it.
	 * @param session Session object being terminated. If observer saved a reference to the session -
	 * this is a good opportunity to drop this reference.
	 */
	virtual void onSessionTerminated(std::shared_ptr<Session> session) = 0;

};


/**
 * Server is IPC handler that recieve request and spawns a session with appropriate protocol
 * to handle communications.
 */
struct Server {

	struct BaseConfig {
		/// Maximum number of concurrent connections allowed.
		Solace::uint16		maxConnections{32};

		/// Maximum number of pending connection - backlog.
		Solace::uint16		backlog{32};

		/// Max size in bytes of a message.
		Solace::uint16		maxMessageSize{8192};
	};

	/// Sever listen configuration
	struct Config : public BaseConfig {
		/// List of authentication rules
		Auth::Policy		authPolicy{};
	};


	/**
	 * Network connection listener.
	 * Spawns new session on successful connection.
	 */
	struct ConnectionListener {
		virtual ~ConnectionListener();

		ConnectionListener(Server& server, std::shared_ptr<Auth::Policy> authPolicy, Observer& observer) noexcept
			: _server{server}
			, _authPolicy{Solace::mv(authPolicy)}
			, _observer{observer}
		{
		}

		Server&	server() noexcept { return _server; }

		Observer& observer() noexcept { return _observer; }

		std::shared_ptr<Auth::Policy> authPolicy() noexcept { return _authPolicy; }

		virtual Result<void> terminate() = 0;

	protected:
		Server&							_server;
		/// Auth handlers protecting different 'realms'
		std::shared_ptr<Auth::Policy>	_authPolicy;

		/// Observer of sessions
		Observer&						_observer;
	};



public:

	/**
	 * Construct a new instance of a server.
	 * @param iocontext IO context used for communications.
	 * @param vfs Filesystem to be served by the server instance.
	 * @param memManager Memory manager used for mmeory allocation.
	 */
	Server(asio::io_context& iocontext, kasofs::Vfs& vfs, Solace::MemoryManager& memManager) noexcept
		: _iocontext{iocontext}
		, _memManager{memManager}
		, _vfs{vfs}
	{}

	asio::io_context& iocontext() noexcept { return _iocontext; }
	asio::io_context const& iocontext() const noexcept { return _iocontext; }

	Solace::MemoryManager& memoryManager() noexcept { return _memManager; }
	Solace::MemoryManager const& memoryManager() const noexcept { return _memManager; }

	kasofs::Vfs& vfs() noexcept { return _vfs; }
	kasofs::Vfs const& vfs() const noexcept { return _vfs; }

	/**
	 * Begin listening for incomming connections using given configuration
	 * @param endpoint Endpoint to listen on for connections.
	 * @param config Options for listening
	 * @return A new state of the server
	 */
	Result<std::shared_ptr<ConnectionListener>>
	listen(Solace::DialString endpoint, Config&& config, Observer& sessionObserver);


private:

	/// IO context used for async operations
	asio::io_context&			_iocontext;
	/// Memory manager used for memory allocation.
	Solace::MemoryManager&		_memManager;
	/// Resource served by the server instance.
	kasofs::Vfs&				_vfs;
};

}  // end of namespace apsio
#endif  // APSIO_SERVER_HPP
