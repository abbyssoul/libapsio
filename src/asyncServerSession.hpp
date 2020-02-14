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
#ifndef APSIO_SRC_ASYNCSERVERSESSION_HPP
#define APSIO_SRC_ASYNCSERVERSESSION_HPP

#include "asio_utils.hpp"
#include "apsio/server.hpp"

#include "authFile.hpp"

#include <styxe/styxe.hpp>
#include <kasofs/kasofs.hpp>

#include <solace/memoryResource.hpp>
#include <solace/byteReader.hpp>
#include <solace/byteWriter.hpp>


#include <asio/ip/tcp.hpp>
#include <asio/local/stream_protocol.hpp>

#include <asio/read.hpp>
#include <asio/write.hpp>

#include <memory>  // std::unique_ptr
#include <unordered_map>


namespace apsio {

void logConnection(asio::local::stream_protocol::socket const& channel);
void logConnection(asio::ip::tcp::socket const& channel);


namespace impl {



/**
 * 9p Message handler until protocol version has been negotiated
 */
struct UnversionedSessionHandler {
	constexpr UnversionedSessionHandler(styxe::size_type maxPayloadSize) noexcept
		: baseParser{maxPayloadSize}
	{}

	styxe::UnversionedParser				baseParser;
};

// UnversionedSessionHandler type requirements
static_assert(std::is_move_assignable_v<UnversionedSessionHandler>, "UnversionedSessionHandler should be movable");
static_assert(std::is_move_constructible_v<UnversionedSessionHandler>);


/**
 * 9p Message handler for un-authenticated state
 */
struct UnauthenticatedSessionHandler : public UnversionedSessionHandler {

	UnauthenticatedSessionHandler(styxe::RequestParser&& parser,
								  std::shared_ptr<Auth::Policy> auth,
								  UnversionedSessionHandler&& baseHandler) noexcept
		: UnversionedSessionHandler{Solace::mv(baseHandler)}
		, _parser{Solace::mv(parser)}
		, _authPolicy{Solace::mv(auth)}
	{}

	styxe::RequestParser&			parser() noexcept		{ return _parser; }
	std::shared_ptr<Auth::Policy>	authPolicy() noexcept	{ return _authPolicy; }

	Auth::Strategy&			findAuthStrategy(Solace::StringView uname,
											 Solace::Optional<Solace::uint32> uid,
											 Solace::StringView resource);
	Result<kasofs::User>	authenticate(styxe::Fid afid,
										 Solace::StringView name,
										 Solace::Optional<Solace::uint32> uid,
										 Solace::StringView resource);

	styxe::Qid beginAuth(styxe::Fid fid, AuthFile&& file);
	Result<AuthFile&>		findAuthForFid(styxe::Fid fid);


	styxe::RequestParser						_parser;
	std::shared_ptr<Auth::Policy>				_authPolicy;

	/// Active auth 'files'
	std::unordered_map<styxe::Fid, AuthFile>   _fidToAuth;
};

// UnauthenticatedSessionHandler type requirements
static_assert(std::is_move_assignable_v<UnauthenticatedSessionHandler>);
static_assert(std::is_move_constructible_v<UnauthenticatedSessionHandler>);


/**
 * 9p Message handler for an established session
 */
struct SessionProtocolHandler final : public UnauthenticatedSessionHandler {
	using size_type = styxe::size_type;


	SessionProtocolHandler(kasofs::User user, kasofs::Vfs& vfs,
						   styxe::Fid fid, Solace::StringView aname, kasofs::INode::Id id,

						   UnauthenticatedSessionHandler&& handler) noexcept
		: UnauthenticatedSessionHandler{Solace::mv(handler)}
		, _vfs{vfs}
		, _user{user}
	{
		hashFid(fid, aname, id);
	}

	kasofs::Vfs& vfs() noexcept							{ return _vfs; }
	kasofs::User user() noexcept						{ return _user; }


	void hashFid(styxe::Fid fid, Solace::StringView name, kasofs::INode::Id nodeIndex) noexcept {
		_fidToEntry.try_emplace(fid, name, nodeIndex);
	}

	void hashFid(styxe::Fid fid, kasofs::Entry entry) noexcept {
		_fidToEntry.try_emplace(fid, entry);
	}

	void removeEntryByFid(styxe::Fid fid) {
		_fidToEntry.erase(fid);
	}

	Solace::Optional<kasofs::Entry>
	entryByFid(styxe::Fid fid) const noexcept {
		auto it = _fidToEntry.find(fid);
		if (it == _fidToEntry.end()) {
			return Solace::none;
		}

		return {it->second};
	}


	auto addOpened(styxe::Fid fid, kasofs::File&& file) {
		return _openedNodes.emplace(fid, Solace::mv(file)).first;
	}

	Solace::Optional<kasofs::File*>
	findOpened(styxe::Fid fid) {
		auto it = _openedNodes.find(fid);
		if (it == _openedNodes.end()) {
			return Solace::none;
		}

		return { &(it->second) };
	}

	void removeOpened(styxe::Fid fid) {
		_openedNodes.erase(fid);
	}

private:
	std::reference_wrapper<kasofs::Vfs>		_vfs;
	kasofs::User							_user;

	// Cache
	std::unordered_map<styxe::Fid, kasofs::File>	_openedNodes;
	std::unordered_map<styxe::Fid, kasofs::Entry>   _fidToEntry;
};

// SessionProtocolHandler type requirements
static_assert(std::is_move_assignable_v<SessionProtocolHandler>, "SessionProtocolHandler should be movable");
static_assert(std::is_move_constructible_v<SessionProtocolHandler>);


/// Session handler state
using SessionHandler = std::variant<UnversionedSessionHandler, UnauthenticatedSessionHandler, SessionProtocolHandler>;

// SessionHandler type requirements
static_assert(std::is_move_assignable_v<SessionHandler>, "SessionHandler should be movable");
static_assert(std::is_move_constructible_v<SessionHandler>);


/**
 * Base class for Async sessions
 */
struct AsyncSessionBase :
		public Session,
		public std::enable_shared_from_this<AsyncSessionBase>
{

	AsyncSessionBase(Server& server,
					 std::shared_ptr<Auth::Policy> authPolicy,
					 Observer& observer,
					 Server::BaseConfig config,
					 Solace::MemoryResource&& inBuffer,
					 Solace::MemoryResource&& outBuffer) noexcept
		: Session{server, Solace::mv(authPolicy), observer}
		, _protocolHandler{UnversionedSessionHandler(config.maxMessageSize - styxe::headerSize())}
		, _requestBuffer{Solace::mv(inBuffer)}
		, _responseBuffer{Solace::mv(outBuffer)}
	{
	}

	Result<void> terminate() override = 0;

	void logError(asio::error_code const& ec) const;
	void logError(Error const& ec) const;

	void logHeader(styxe::MessageHeader const& header, const char* dirGlyph) const;

	virtual void start();

protected:

	Result<styxe::MessageHeader>
	parseMessageHeader(Solace::ByteReader& reader) const;

	Result<void>
	handleRequest(styxe::MessageHeader header, Solace::ByteReader& payloadReader, Solace::ByteWriter& responseWriter);

	void
	switchState(SessionHandler&& newHandler) noexcept {
		_protocolHandler = Solace::mv(newHandler);
	}

protected:

	/// State of the session:
	SessionHandler			_protocolHandler;

	// IO Buffers
	Solace::MemoryResource  _requestBuffer;
	Solace::MemoryResource  _responseBuffer;

	/// Storage buffer to read inbound fixed-size message header
	Solace::byte			_headerStorage[styxe::headerSize()];
};



template<typename ProtocolType>
class AsyncSession final :
		public AsyncSessionBase
{
public:
	using Endpoint = typename ProtocolType::endpoint;
	using Socket = typename ProtocolType::socket;

	AsyncSession(AsyncSession const&) = delete;
	AsyncSession& operator= (AsyncSession const&) = delete;

	AsyncSession(Socket&& channel,
				Server& server,
				std::shared_ptr<Auth::Policy> authPolicy,
				Observer& observer,
				Server::BaseConfig config,
				Solace::MemoryResource&& in,
				Solace::MemoryResource&& out)
		: AsyncSessionBase{server, Solace::mv(authPolicy), observer, config, Solace::mv(in), Solace::mv(out)}
		, _channel{Solace::mv(channel)}
		, _remoteEndpoint{_channel.remote_endpoint()}
	{
	}


	Result<void> terminate() override {
		notifyObserver();

		asio::error_code ec;
		_channel.close(ec);
		if (ec) {
			return fromAsioError(ec);
		}

		return Solace::Ok();
	}

	void start() override {
		doRead();
	}

protected:

	void notifyObserver() {
		if (!_isTerminated) {
			_isTerminated = true;
			observer().onSessionTerminated(shared_from_this());
		}
	}

	void terminate(Error const& ec) {
		logError(ec);
		terminate();
	}

	void terminate(asio::error_code const& ec) {
		logError(ec);
		terminate();
	}

	void doRead() {
		asio::async_read(_channel, asio_buffer(Solace::wrapMemory(_headerStorage)),  // read fixed-size message header
				[self = shared_from_this(), this] (asio::error_code const& ec, std::size_t bytesRead) {
					if (ec) {  // Error, don't schedule more comms. drop session.
						terminate(ec);
						return;
					}

					auto reader = Solace::ByteReader{Solace::wrapMemory(_headerStorage).slice(0, bytesRead)};
					parseMessageHeader(reader)
							.then([this](styxe::MessageHeader&& header) {
								logHeader(header, "→");
								readPayload(header);
							}).orElse([this](Error const& e) {
								terminate(e);
							});
				});
	}

	void readPayload(styxe::MessageHeader header) {
		asio::async_read(_channel, asio_buffer(_requestBuffer.view().slice(0, header.payloadSize())),
			[self = shared_from_this(), this, header] (asio::error_code const& ec, std::size_t bytesRead) {
				if (ec) {  // Error, don't schedule more comms. drop session.
					terminate(ec);
					return;
				}

				auto payloadReader  = Solace::ByteReader{_requestBuffer.view().slice(0, bytesRead)};
				auto responseWriter = Solace::ByteWriter{_responseBuffer};

				handleRequest(header, payloadReader, responseWriter)
					.then([this, &responseWriter]() {
						writeResponse(responseWriter);
					}).orElse([this](auto const& er) {
						terminate(er);
					});
		});
	}


	void writeResponse(Solace::ByteWriter& responseData) {
		asio::async_write(_channel, asio_buffer(responseData.viewWritten()),
				[self = shared_from_this(), this](asio::error_code const& ec, std::size_t /*bytesWriten*/) {
					if (ec) {  // Error, don't schedule more comms. drop session.
						terminate(ec);
						return;
					}

					// TODO(abbyssoul): Do we handle partial writes?
					// responseData.advance(bytesWriten)
					// while (responseData.hasRemaining()) {...}
					doRead();
				});
	}

private:
	Socket      _channel;
	Endpoint    _remoteEndpoint;    // Remote peer endpoint. Save for logging as it may be not avaliable in some cases.
	bool		_isTerminated{false};
};


template<typename Protocol>
std::shared_ptr<AsyncSessionBase>
makeSession(typename Protocol::socket&& channel,
			Server& server,
			std::shared_ptr<Auth::Policy> authPolicy,
			Observer& observer,
			Server::BaseConfig config,
			Solace::MemoryResource&& inBuf,
			Solace::MemoryResource&& outBuf) {
	return std::make_shared<AsyncSession<Protocol>>(Solace::mv(channel),
												   server,
												   authPolicy,
												   observer,
												   config,
												   Solace::mv(inBuf),
												   Solace::mv(outBuf));
}

}  // namespace impl



template<typename Protocol>
Result<std::shared_ptr<impl::AsyncSessionBase>>
spawnSession(typename Protocol::socket&& channel,
			 Server& server,
			 std::shared_ptr<Auth::Policy> authPolicy,
			 Observer& observer,
			 Server::BaseConfig config)
{
	logConnection(channel);

	auto& memoryManager = server.memoryManager();
	// TODO(abbyssoul): Review memory allocation strategy used
	auto inBuf  = memoryManager.allocate(config.maxMessageSize);
	auto outBuf = memoryManager.allocate(config.maxMessageSize);
	if (!inBuf)
		return inBuf.moveError();
	if (!outBuf)
		return outBuf.moveError();

	// TODO(abbyssoul): Can we avoid memory allocation here and re-use / garbege collect memory?
	return impl::makeSession<Protocol>(Solace::mv(channel),
									   server,
									   authPolicy,
									   observer,
									   config,
									   inBuf.moveResult(),
									   outBuf.moveResult());
}


}  // namespace apsio
#endif  // APSIO_SRC_ASYNCSERVERSESSION_HPP
