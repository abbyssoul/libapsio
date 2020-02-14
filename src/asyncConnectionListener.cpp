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
#include "asyncConnectionListener.hpp"

#include <asio/ip/tcp.hpp>
#include <asio/local/stream_protocol.hpp>


using namespace Solace;
using namespace styxe;


apsio::Result<void> apsio::AsyncServerBase::terminate() { return Ok(); }


Result<void, asio::error_code>
apsio::impl::startAcceptor(asio::local::stream_protocol::acceptor& acceptor, DialString const& ds) {
	asio::error_code ec;

	auto const localEndpoint = asio::local::stream_protocol::endpoint{as_string(ds.address)};

	acceptor.open(localEndpoint.protocol(), ec);
	if (ec) {
		return ec;
	}

	// Unlink before bind
	if (unlink(localEndpoint.path().c_str())) {
		if (errno != ENOENT) {
			return std::make_error_code(static_cast<std::errc>(errno));
		}
	}

	acceptor.bind(localEndpoint, ec);
	if (ec) {
		return ec;
	}

	acceptor.listen(asio::socket_base::max_listen_connections, ec);
	if (ec) {
		return ec;
	}

	return Ok();
}



Result<void, asio::error_code>
apsio::impl::startAcceptor(asio::ip::tcp::acceptor& acceptor, DialString const& ds) {
	asio::error_code ec;

	auto const localAddress = asio::ip::make_address(as_string(ds.address), ec);
	if (ec) {
		return ec;
	}

	// FIXME: Use uint16 parser to catch uint16 overflow
	uint16 const port = std::strtoul(ds.service.data(), nullptr, 10);
	auto localEndpoint = asio::ip::tcp::endpoint{localAddress, port};

	acceptor.open(localEndpoint.protocol(), ec);
	if (ec) {
		return ec;
	}

	acceptor.bind(localEndpoint, ec);
	if (ec) {
		return ec;
	}

	acceptor.listen(asio::socket_base::max_listen_connections, ec);
	if (ec) {
		return ec;
	}

	return Ok();
}


apsio::Result<std::shared_ptr<apsio::AsyncServerBase>>
apsio::createServer(AtomValue protocol, Server& server, Observer& observer, Server::Config&& config) {
#ifdef ASIO_HAS_LOCAL_SOCKETS
	if (styxe::kProtocolUnix == protocol) {
		return makeListener<asio::local::stream_protocol>(server,
														  std::make_shared<Auth::Policy>(mv(config.authPolicy)),
														  observer,
														  config);
	}
#endif
	if (styxe::kProtocolTCP == protocol) {
		return makeListener<asio::ip::tcp>(server,
										   std::make_shared<Auth::Policy>(mv(config.authPolicy)),
										   observer,
										   config);
	}

	return makeError(GenericError::IO, "listen: not supported protocol");
}

