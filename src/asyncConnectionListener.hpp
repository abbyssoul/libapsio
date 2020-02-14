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
#ifndef APSIO_SRC_ASYNCCONNECTIONLISTENER_HPP
#define APSIO_SRC_ASYNCCONNECTIONLISTENER_HPP


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
 * Create a new instance of a connection listener for a given protocol.
 * @param protocol Protocol to create a listener for.
 * @param server IO object
 * @param observer Session lifecycle observer
 * @param config Listener configuration
 * @return A resulting listener or an error.
 */
Result<std::shared_ptr<AsyncServerBase>>
createServer(Solace::AtomValue protocol,
			 Server& server,
			 Observer& observer,
			 Server::Config&& config);

}  // namespace apsio
#endif  // APSIO_SRC_ASYNCCONNECTIONLISTENER_HPP
