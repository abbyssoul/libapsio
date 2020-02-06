/*
*  Copyright (C) Ivan Ryabov - All Rights Reserved
*
*  Unauthorized copying of this file, via any medium is strictly prohibited.
*  Proprietary and confidential.
*
*  Written by Ivan Ryabov <abbyssoul@gmail.com>
*/
#pragma once
#ifndef APSIO_ASYNCCONNECTIONLISTENER_HPP
#define APSIO_ASYNCCONNECTIONLISTENER_HPP


#include "asyncServerSession.hpp"
#include "apsio/server.hpp"


namespace apsio {


struct AsyncServerBase :
		public Server::ConnectionListener,
		public std::enable_shared_from_this<AsyncServerBase>
{
	AsyncServerBase(Server& server, std::shared_ptr<Auth::Policy> authPolicy, Observer& observer) noexcept
		: Server::ConnectionListener{server, Solace::mv(authPolicy), observer}
	{}

	Result<void> terminate() override;

	virtual Result<void> listen(styxe::DialString ds) = 0;
};


namespace impl {

Solace::Result<void, asio::error_code>
startAcceptor(asio::local::stream_protocol::acceptor& acceptor, styxe::DialString const& config);

Solace::Result<void, asio::error_code>
startAcceptor(asio::ip::tcp::acceptor& acceptor, styxe::DialString const& config);


/**
 * @brief A server that listen on a local socket.
 */
template<typename ProtocolType>
struct AsyncServer final :
		public AsyncServerBase
{
	using Acceptor = typename ProtocolType::acceptor;
	using Socket = typename ProtocolType::socket;

	// Non copy-constructable
	AsyncServer(AsyncServer const&) = delete;
	AsyncServer& operator= (AsyncServer const&) = delete;

	AsyncServer(Server& server, std::shared_ptr<Auth::Policy> authPolicy, Observer& observer, Server::BaseConfig config)
		: AsyncServerBase{server, Solace::mv(authPolicy), observer}
		, _config{Solace::mv(config)}
		, _acceptor{_server.iocontext()}
	{
	}

	Result<void>
	listen(styxe::DialString ds) override {
		auto startResult = startAcceptor(_acceptor, ds);
		if (!startResult) {
			return fromAsioError(startResult.getError());
		}

		_boundTo = ds;
		doAccept();

		return Solace::Ok();
	}


	Result<void>
	terminate() override {
		asio::error_code ec;
		_acceptor.close(ec);
		if (ec) {
			return fromAsioError(ec);
		}

		return Solace::Ok();
	}

protected:

	void doAccept() {
		_acceptor.async_accept([self = shared_from_this(), this] (asio::error_code const& ec, Socket&& peer) {
			if (ec) {
				observer().onError(_boundTo, fromAsioError(ec));
				return;
			}

			auto session = spawnSession<ProtocolType>(Solace::mv(peer), server(), authPolicy(), observer(), _config);
			if (!session) {
				observer().onError(_boundTo, session.getError());
			} else {
				(*session)->start();
				observer().onSessionAccepted(_boundTo, session.moveResult());
			}

			doAccept();
		});
	}

private:
	/// Network connection acceptor
	Server::BaseConfig			_config;
	Acceptor			        _acceptor;

	styxe::DialString			_boundTo;
};


}  // namespace impl



template<typename Protocol>
std::shared_ptr<AsyncServerBase>
makeListener(Server& server, std::shared_ptr<Auth::Policy> authPolicy, Observer& observer, Server::BaseConfig config) {
	// TODO(abbyssoul): Should we use memory manager to allocate listener too?
	return std::make_shared<impl::AsyncServer<Protocol>>(server, Solace::mv(authPolicy), observer, config);
}

/**
 * Create a new instance of a connection acceptor for a given protocol.
 * @param protocol Protocol to create an acceptor for.
 * @param server IO object
 * @param observer Session lifecycle observer
 * @param config Listener configuration
 * @return
 */
Result<std::shared_ptr<AsyncServerBase>>
createServer(Solace::AtomValue protocol,
			 Server& server,
			 Observer& observer,
			 Server::Config&& config);

}  // namespace apsio
#endif  // APSIO_ASYNCCONNECTIONLISTENER_HPP
