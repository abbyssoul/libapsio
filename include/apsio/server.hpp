/*
*  Copyright (C) Ivan Ryabov - All Rights Reserved
*
*  Unauthorized copying of this file, via any medium is strictly prohibited.
*  Proprietary and confidential.
*
*  Written by Ivan Ryabov <abbyssoul@gmail.com>
*/
#pragma once
#ifndef APSIO_SERVER_HPP
#define APSIO_SERVER_HPP

#include "types.hpp"
#include "auth.hpp"

#include <kasofs/kasofs.hpp>
#include <dialstring/dialstring.hpp>

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
	{}

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


struct Observer {
	virtual ~Observer();

	virtual void onSessionAccepted(styxe::DialString listenerInterface, std::shared_ptr<Session> newSession) = 0;

	// Connection listeners signals:
	virtual void onAcceptFailed(styxe::DialString listenerInterface, Error error) = 0;

	virtual void onSessionTerminated(Session* session) = 0;

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
		Solace::uint16		maxMessageSize{1024};
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
		{}

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
	listen(styxe::DialString endpoint, Config&& config, Observer& sessionObserver);



private:

	/// IO context used for async operations
	asio::io_context&			_iocontext;
	/// Memory manager used for memory allocation.
	Solace::MemoryManager&		_memManager;
	/// Resource served by the server instance.
	kasofs::Vfs&				_vfs;
};


struct SimpleServer final :
		public Server,
		public Observer
{
	SimpleServer(asio::io_context& iocontext, kasofs::Vfs& vfs, Solace::MemoryManager& memManager) noexcept
		: Server{iocontext, vfs, memManager}
	{}


	// Connection listeners signals:
	void onAcceptFailed(styxe::DialString endpoint, Error error) override;

	void onSessionAccepted(styxe::DialString endpoint, std::shared_ptr<Session> newSession) override;
	void onSessionTerminated(Session* session) override;


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
#endif  // APSIO_SERVER_HPP
