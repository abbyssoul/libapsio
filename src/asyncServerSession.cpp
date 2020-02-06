/*
*  Copyright (C) Ivan Ryabov - All Rights Reserved
*
*  Unauthorized copying of this file, via any medium is strictly prohibited.
*  Proprietary and confidential.
*
*  Written by Ivan Ryabov <abbyssoul@gmail.com>
*/
#include "asyncServerSession.hpp"

#include <styxe/styxe.hpp>

#include <solace/output_utils.hpp>
#include <solace/posixErrorDomain.hpp>

#include <iostream>  // std::clog
#include <iomanip>   // std::setw


using namespace Solace;
using namespace apsio;
using namespace apsio::impl;



void apsio::logConnection(asio::local::stream_protocol::socket const& channel) {
	std::clog << "Local connection from: '"
			  << channel.remote_endpoint() << '\''
			  << std::endl;
}

void apsio::logConnection(asio::ip::tcp::socket const& channel) {
	std::clog << "Remote connection from: '"
			  << channel.remote_endpoint().address() << ':' << channel.remote_endpoint().port() << '\''
			  << std::endl;
}


//NOTE: The only reason to have it here - is to not emit vtable in each translation unit.
void AsyncSessionBase::start() {}


namespace /*anonymous */ {

kasofs::Permissions
modeToOp(styxe::OpenMode mode) {
	switch (mode.mode & 0x03) {
	case styxe::OpenMode::READ:  return kasofs::Permissions::READ;
	case styxe::OpenMode::WRITE: return kasofs::Permissions::WRITE;
	case styxe::OpenMode::RDWR:  return kasofs::Permissions::READ | kasofs::Permissions::WRITE;
	case styxe::OpenMode::EXEC:  return kasofs::Permissions::EXEC;
	default:
		return 0;
	}
}


styxe::QidType
mapType(kasofs::VfsId nodeType) noexcept {
	if (nodeType == kasofs::Vfs::kVfsTypeDirectory) {
		return styxe::QidType::DIR;
	}

//	case kasofs::INode::Type::Data:        return styxe::QidType::FILE;
//    case vfs::INode::Type::Synthetic:   return styxe::QidType::TMP;
//    case vfs::INode::Type::SyntheticDir:   return styxe::QidType::DIR;
//	}

	// NOTE: We probably should halt at this point
	return styxe::QidType::FILE;
}

styxe::Qid
nodeToQid(kasofs::INode const& inode) noexcept {
	return styxe::Qid {
		inode.vfsData,
		inode.version,
		static_cast<byte>(mapType(inode.fsTypeId))
	};
}


styxe::Qid
authQid(AuthFile const& SOLACE_UNUSED(strategy)) noexcept {
	return styxe::Qid{0, 0, static_cast<byte>(styxe::QidType::AUTH)};
}


styxe::Stat
nodeStats(StringView name, kasofs::INode const& inode) {
	styxe::Stat stats;

	stats.qid = nodeToQid(inode);
	stats.name = name;
	stats.mode = inode.permissions.value;
	stats.atime = inode.atime;
	stats.mtime = inode.mtime;
	stats.length = inode.dataSize;

//    stats.uid;        //!< owner name
//    stats.gid;        //!< group name
//    stats.muid;       //!< name of the user who last modified the file

	// Size the stats struct
	stats.size = styxe::DirListingWriter::sizeStat(stats);

	return stats;
}



StringView selectProtocol(StringView requestedVersion) {
	// 9p version: The string must always begin with the two characters “9P”
	if (!requestedVersion.startsWith("9P")) {
		return styxe::kUnknownProtocolVersion;
	}

//	// If we can only server sub-version
//	if (req.version.startsWith(parser.PROTOCOL_VERSION)) {
//		negotiatedVersion = parser.PROTOCOL_VERSION;
//	} else if (parser.PROTOCOL_VERSION.startsWith(req.version))
//		negotiatedVersion = req.version;

	return styxe::kProtocolVersion;
}



struct SessionStateTransition {
	styxe::MessageHeader	responseHeader;
	SessionHandler			newHandler;
};


apsio::Result<SessionStateTransition>
unsupportedMessage() /*noexcept */{
	return makeError(GenericError::PERM, "unsupported");
}


}  // namespace anonymous



apsio::Result<AuthFile&>
UnauthenticatedSessionHandler::beginAuthentication(styxe::Fid afid, StringView uname, StringView resource) {
	auto& strategy = authPolicy()->findAuthStrategyFor({uname, resource});

	auto it = _fidToAuth.try_emplace(afid, AuthFile{uname, resource, strategy});
	return apsio::Result<AuthFile&>{types::okTag, std::ref(it.first->second)};
}


apsio::Result<kasofs::User>
UnauthenticatedSessionHandler::authenticate(styxe::Fid afid, StringView name, StringView resource) {
	auto it = _fidToAuth.find(afid);
	if (it == _fidToAuth.end()) {
		return makeError(GenericError::IO, "authenticate");
	}

	auto& authFile = it->second;
	return authFile.authenticate(name, resource);
}


apsio::Result<AuthFile&>
UnauthenticatedSessionHandler::findAuthForFid(styxe::Fid fid) {
	auto it = _fidToAuth.find(fid);
	if (it == _fidToAuth.end())
		return makeError(GenericError::IO, "find");

	return Result<AuthFile&>{types::okTag, std::ref(it->second)};
}



struct BaseRequestVisiter {
	apsio::Result<SessionStateTransition> operator()(styxe::Request::Version const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::Request::Auth const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::Request::Flush const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::Request::Attach const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::Request::Walk const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::Request::Open const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::Request::Create const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::Request::Read const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::Request::Write const&){ return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::Request::Clunk const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::Request::Remove const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::Request::Stat const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::Request::WStat const&) { return unsupportedMessage(); }

	apsio::Result<SessionStateTransition> operator()(styxe::_9P2000U::Request::Auth const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::_9P2000U::Request::Attach const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::_9P2000U::Request::Create const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::_9P2000U::Request::WStat const&) { return unsupportedMessage(); }

	apsio::Result<SessionStateTransition> operator()(styxe::_9P2000E::Request::Session const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::_9P2000E::Request::ShortRead const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::_9P2000E::Request::ShortWrite const&) { return unsupportedMessage(); }

	apsio::Result<SessionStateTransition> operator()(styxe::_9P2000L::Request::StatFS const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::_9P2000L::Request::LOpen const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::_9P2000L::Request::LCreate const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::_9P2000L::Request::Symlink const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::_9P2000L::Request::MkNode const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::_9P2000L::Request::Rename const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::_9P2000L::Request::ReadLink const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::_9P2000L::Request::GetAttr const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::_9P2000L::Request::SetAttr const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::_9P2000L::Request::XAttrWalk const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::_9P2000L::Request::XAttrCreate const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::_9P2000L::Request::ReadDir const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::_9P2000L::Request::FSync const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::_9P2000L::Request::Lock const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::_9P2000L::Request::GetLock const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::_9P2000L::Request::Link const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::_9P2000L::Request::MkDir const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::_9P2000L::Request::RenameAt const&) { return unsupportedMessage(); }
	apsio::Result<SessionStateTransition> operator()(styxe::_9P2000L::Request::UnlinkAt const&) { return unsupportedMessage(); }
};


struct UnversionedRequestVisiter : public BaseRequestVisiter {
	using BaseRequestVisiter::operator();

	apsio::Result<SessionStateTransition> operator()(styxe::Request::Version const& req) {
		const auto minMessageSize = std::min(unversionedHandler.baseParser.maxMessageSize(), req.msize);

		auto negotiatedVersion = selectProtocol(req.version);

		// The version proposed is not supported - reply with 'UnknownProtocolVersion'
		if (styxe::kUnknownProtocolVersion.equals(negotiatedVersion)) {
			responseWriter << styxe::Response::Version{minMessageSize, negotiatedVersion};
			return responseOk();
		}

		auto versionedParser = styxe::createRequestParser(negotiatedVersion, minMessageSize);
		if (!versionedParser) {  // In case we failed to create a parser for selected version reply with 'UnknownProtocolVersion'
			responseWriter << styxe::Response::Version{minMessageSize, styxe::kUnknownProtocolVersion};
			return responseOk();
		}

		// Propose selected version and switch parser for a versioned one.
		responseWriter << styxe::Response::Version{minMessageSize, negotiatedVersion};
		return responseOkAndTransit(UnauthenticatedSessionHandler{versionedParser.moveResult(), authPolicy, mv(unversionedHandler)});
	}

	apsio::Result<SessionStateTransition>
	responseOk() {
		return SessionStateTransition{responseWriter.header(), mv(unversionedHandler)};
	}

	apsio::Result<SessionStateTransition>
	responseOkAndTransit(SessionHandler&& newSessionHandler) {
		return SessionStateTransition{responseWriter.header(), mv(newSessionHandler)};
	}


	apsio::Result<SessionStateTransition>
	error(SessionHandler&& newSessionHandler, StringView message) {
		responseWriter << styxe::Response::Error{message};
		return SessionStateTransition{responseWriter.header(), mv(newSessionHandler)};
	}

	apsio::Result<SessionStateTransition>
	error(SessionHandler&& newSessionHandler, GenericError SOLACE_UNUSED(errCode), StringView message) {
		responseWriter << styxe::Response::Error{message};
		return SessionStateTransition{responseWriter.header(), mv(newSessionHandler)};
	}

	apsio::Result<SessionStateTransition>
	error(SessionHandler&& newSessionHandler, Error const& err) {
		auto const domain = getErrorDomain(err.domain());
		if (domain) {
			return error(mv(newSessionHandler), (*domain)->message(err.value()).view());
		}

		// In case domain is not known:
		constexpr auto const N = sizeof(AtomValue);
		char domainName[N + 1] = {0};
		atomToString(err.domain(), domainName);

		responseWriter << styxe::Response::Partial::Error{}
						<< StringView{domainName}
						<< StringView{": "}
						<< err.tag();

		return SessionStateTransition{responseWriter.header(), mv(newSessionHandler)};
	}


	UnversionedRequestVisiter(styxe::Tag responseTag, ByteWriter& outputStream, UnversionedSessionHandler& handler, std::shared_ptr<Auth::Policy> auth)
		: unversionedHandler{handler}
		, authPolicy{mv(auth)}
		, responseWriter{outputStream, responseTag}
	{}

	UnversionedSessionHandler&		unversionedHandler;
	std::shared_ptr<Auth::Policy>	authPolicy;

	styxe::ResponseWriter		responseWriter;
};


struct UnauthenticatedRequestVisiter: public UnversionedRequestVisiter {

	using UnversionedRequestVisiter::operator();

	auto responseOk() { return responseOkAndTransit(mv(_unauthenticatedHandler)); }
	auto responseNAK(StringView message) { return error(mv(_unauthenticatedHandler), message); }
	auto responseNAK(Error const& err) { return error(mv(_unauthenticatedHandler), err); }
	auto responseNAK(GenericError errCode, StringView message) { return error(mv(_unauthenticatedHandler), errCode, message); }


	apsio::Result<SessionStateTransition> operator()(styxe::Request::Auth const& req) {
		// Prepare authentication mechanism for a new user idenfied as req.uname who wants to access resource req.aname

		// SEC: Note: do NOT open a new auth file for each auth requiest - as it can lean to DoS

		// TODO: Even if user name is not valid - but authentication is enabled - we should reply with ok, not error
		auto maybeAuthFile = _unauthenticatedHandler.beginAuthentication(req.afid, req.uname, req.aname);
		if (!maybeAuthFile) {
			// ???? Internal server error! Close the session
			responseWriter << styxe::Response::Auth{};
			return responseOk();
		}

		auto& authFile = *maybeAuthFile;
		if (!authFile.isAuthRequired()) {
			return responseNAK("Auth not required");
		}

		responseWriter << styxe::Response::Auth{authQid(authFile)};
		return responseOk();
	}


	apsio::Result<SessionStateTransition> operator()(styxe::Request::Attach const& req) {
		auto user = _unauthenticatedHandler.authenticate(req.afid, req.uname, req.aname);
		if (!user) {  // Authentication failed / incomplete
			return responseNAK(GenericError::ACCES, "attach");
		}

		SessionProtocolHandler sessionHandler{*user, _vfs, mv(_unauthenticatedHandler)};
		return responseOkAndTransit(mv(_unauthenticatedHandler));
	}


	// Note: It should be possible to read data from afid if selected authentication scheme supports it
	apsio::Result<SessionStateTransition> operator()(styxe::Request::Read const& req) {
		auto maybeStrategy = _unauthenticatedHandler.findAuthForFid(req.fid);
		if (!maybeStrategy) {
			return responseNAK("Not attached fid");
		}
//		AuthStrategy& strategy = (*maybeStrategy);

//		responseWriter << styxe::Response::Read{*maybeBytesWritten};

		return unsupportedMessage();
	}


	// Note: Write call is used to write authentication details into provided afid
	apsio::Result<SessionStateTransition> operator()(styxe::Request::Write const& req) {
		auto maybeStrategy = _unauthenticatedHandler.findAuthForFid(req.fid);
		if (!maybeStrategy) {
			return responseNAK("Not attached fid");
		}

		AuthFile& strategy = (*maybeStrategy);
		auto maybeBytesWritten = strategy.write(req.data, req.offset);
		if (!maybeBytesWritten) {
			return responseNAK(maybeBytesWritten.getError());
		}

		responseWriter << styxe::Response::Write{narrow_cast<styxe::size_type>(*maybeBytesWritten)};
		return responseOk();
	}


	UnauthenticatedRequestVisiter(styxe::Tag responseTag,
								  ByteWriter& outputStream,
								  UnauthenticatedSessionHandler& handler,
								  kasofs::Vfs& vfs)
		: UnversionedRequestVisiter{responseTag, outputStream, handler, handler.authPolicy()}
		, _unauthenticatedHandler{handler}
		, _vfs{vfs}
	{}

	UnauthenticatedSessionHandler&  _unauthenticatedHandler;
	kasofs::Vfs&					_vfs;
};


/**
 * Handler for Styxe Request messages
 * It is to be used as a visiter of styxe::Request variant
 */
struct StyxeRequestVisiter final : public UnauthenticatedRequestVisiter {

	using UnauthenticatedRequestVisiter::operator();

	auto responseOk() { return responseOkAndTransit(mv(sessionHandler)); }
	auto responseNAK(StringView message) { return error(mv(sessionHandler), message); }
	auto responseNAK(Error const& err) { return error(mv(sessionHandler), err); }
	auto responseNAK(GenericError errCode, StringView message) { return error(mv(sessionHandler), errCode, message); }

	apsio::Result<SessionStateTransition> operator()(styxe::Request::Walk const& req) {
//		auto maybeUser = sessionHandler.user();
//		if (!maybeUser)
//			return responseNAK(GenericError::ACCES, "walk");

		auto const maybeEntry = sessionHandler.entryByFid(req.fid);
		if (!maybeEntry) {
			return responseNAK("Not attached fid");
		}

		// TODO: Make sure newFid is closed
		auto const maybeNewFid = sessionHandler.entryByFid(req.newfid);
		if (maybeNewFid) {
			return responseNAK("Fid already in use");
		}

		if (req.path.empty()) {  // Requesting fid dup:
			sessionHandler.hashFid(req.newfid, *maybeEntry);  // Copy entry adn associate it with a new fid

			responseWriter << styxe::Response::Walk{0, {}};
			return responseOk();
		}

		auto& vfs = sessionHandler.vfs();
		auto& attachmentNode = *maybeEntry;

		// TODO: Support partial Walk response
		// auto pathWriter = responseBuilder << styxe::Response::Partial::Walk

		// FIXME: Protection from a user supplied path length
		styxe::Response::Walk resp{0, {}};
		auto walkResult = vfs.walk(sessionHandler.user(), attachmentNode.nodeId, req.path,
								   [&resp](kasofs::INode const& node) {
										resp.qids[resp.nqids++] = nodeToQid(node);
		// FIXME: Break the walk if more then nquids walked.
									});
		if (!walkResult) {
			return responseNAK(walkResult.getError());
		}

		auto entry = *walkResult;
		sessionHandler.hashFid(req.newfid, entry.name, entry.nodeId);

		responseWriter << resp;
		return responseOk();
	}


	apsio::Result<SessionStateTransition> operator()(styxe::Request::Open const& req) {
		auto maybeEntry = sessionHandler.entryByFid(req.fid);
		if (!maybeEntry) {
			return responseNAK("Not attached fid");
		}

		auto& entry = *maybeEntry;
		auto maybeFile = sessionHandler.vfs().open(sessionHandler.user(), entry.nodeId, modeToOp(req.mode));
		if (!maybeFile) {
			return responseNAK(maybeFile.getError());
		}

		auto i = sessionHandler.addOpened(req.fid, maybeFile.moveResult());

		kasofs::INode node = i->second.stat();
		responseWriter << styxe::Response::Open{nodeToQid(node), 0};
		return responseOk();
	}


	apsio::Result<SessionStateTransition> operator()(styxe::Request::Stat const& req) {
		auto maybeNode = sessionHandler.entryByFid(req.fid);
		if (!maybeNode) {
			return responseNAK("Not attached fid");
		}

		auto& vfs = sessionHandler.vfs();
		auto& node = *maybeNode;
		auto maybeFsNode = vfs.nodeById(node.nodeId);
		if (!maybeFsNode)
			return responseNAK(GenericError::NOENT, "stat");

		auto nodeMeta = nodeStats(node.name, *maybeFsNode);
		auto const datumSize = styxe::protocolSize(nodeMeta);
		responseWriter << styxe::Response::Stat{
								  narrow_cast<styxe::var_datum_size_type>(datumSize),
								  nodeMeta};
		return responseOk();
	}


	apsio::Result<SessionStateTransition> operator()(styxe::Request::Flush const&) {
		// NOTE: In a single threaded environment - there are no concurrent operations
		responseWriter << styxe::Response::Flush{};
		return responseOk();
	}


	apsio::Result<SessionStateTransition> operator()(styxe::Request::Clunk const& req) {
		auto maybeNode = sessionHandler.entryByFid(req.fid);
		if (!maybeNode) {
			return responseNAK("Not attached");
		}

		sessionHandler.removeOpened(req.fid);
		sessionHandler.removeEntryByFid(req.fid);

		responseWriter << styxe::Response::Clunk{};
		return responseOk();
	}


	apsio::Result<SessionStateTransition> operator()(styxe::Request::Read const& req) {
		auto maybeOk = requiresNode(req.fid, "read");
		if (!maybeOk)
			return responseNAK(maybeOk.getError());

		auto& vfs = sessionHandler.vfs();
		auto [fidEntry, node, user] = *maybeOk;

		if (kasofs::isDirectory(node)) {
			auto dirWriter = styxe::DirListingWriter{responseWriter, req.count, req.offset};
			auto maybeIter = vfs.enumerateDirectory(fidEntry.nodeId, user);
			if (!maybeIter)
				return responseNAK(maybeIter.getError());

			for (auto const& entry : *maybeIter) {
				auto entryNode = vfs.nodeById(entry.nodeId);
				if (!entryNode) {
					return responseNAK(GenericError::IO, "read");
				}

				if (!dirWriter.encode(nodeStats(entry.name, *entryNode))) {
					break;
				}
			}

			return responseOk();
		}

		// Case of a file:
		auto maybeOpenedFile = vfs.open(user, fidEntry.nodeId, kasofs::Permissions::READ);
		if (!maybeOpenedFile)
			return responseNAK(maybeOpenedFile.getError());

		auto& file = (*maybeOpenedFile);
		auto maybeOffset = file.seekRead(req.offset, kasofs::Filesystem::SeekDirection::FromStart);
		if (!maybeOffset)
			return responseNAK(maybeOffset.getError());

		auto dataWriter = responseWriter << styxe::Response::Partial::Read{};

//		dataWriter.
		// FIXME: Broken!
		MutableMemoryView dataDest;
		auto maybeReader = file.read(dataDest);
		if (!maybeReader)
			return responseNAK(maybeReader.getError());

		dataWriter.data(dataDest);

		return responseOk();
	}


	apsio::Result<SessionStateTransition> operator()(styxe::Request::Write const& req) {
		auto maybeOk = requiresNode(req.fid, "write");
		if (!maybeOk)
			return responseNAK(maybeOk.getError());

		auto [fidEntry, node, user] = *maybeOk;

		auto& vfs = sessionHandler.vfs();
		if (kasofs::isDirectory(node)) {  // Writing directories prohibited
			return responseNAK(GenericError::ISDIR, "write");
		}

		// Case of a file:
		auto maybeOpenedFile = vfs.open(user, fidEntry.nodeId, kasofs::Permissions::WRITE);
		if (!maybeOpenedFile)
			return responseNAK(maybeOpenedFile.getError());

		auto& file = (*maybeOpenedFile);
		auto maybeOffset = file.seekWrite(req.offset, kasofs::Filesystem::SeekDirection::FromStart);
		if (!maybeOffset)
			return responseNAK(maybeOffset.getError());

		auto bytesWritten = file.write(req.data);
		if (!bytesWritten) {
			return responseNAK(bytesWritten.getError());
		}

		responseWriter << styxe::Response::Write{narrow_cast<styxe::size_type>(*bytesWritten)};
		return responseOk();
	}


	apsio::Result<SessionStateTransition> operator()(styxe::Request::Create const& )  { return responseNAK("Not supported"); }
	apsio::Result<SessionStateTransition> operator()(styxe::Request::Remove const& )  { return responseNAK("Not supported"); }
	apsio::Result<SessionStateTransition> operator()(styxe::Request::WStat const& )   { return responseNAK("Not supported"); }

	apsio::Result<std::tuple<kasofs::Entry, kasofs::INode, kasofs::User>>
	requiresNode(styxe::Fid fid, StringLiteral tag) {
//		auto maybeUser = sessionHandler.user();
//		if (!maybeUser) {
//			return makeError(GenericError::ACCES, tag);
//		}

		auto maybeEntry = sessionHandler.entryByFid(fid);
		if (!maybeEntry) {
			return makeError(GenericError::BADF, tag);
		}

		auto& entry = *maybeEntry;
		auto maybeNode = sessionHandler.vfs().nodeById(entry.nodeId);
		if (!maybeNode) {
			return makeError(GenericError::IO, tag);
		}

		return Ok(std::make_tuple(entry, *maybeNode, sessionHandler.user()));
	}


	StyxeRequestVisiter(styxe::Tag responseTag, ByteWriter& outputStream, SessionProtocolHandler& handler, kasofs::Vfs& baseVfs)
		: UnauthenticatedRequestVisiter{responseTag, outputStream, handler, baseVfs}
		, sessionHandler{handler}
	{}


	SessionProtocolHandler&		sessionHandler;
};


struct SessionStateHandler {

	apsio::Result<SessionStateTransition> operator()(UnversionedSessionHandler& handler) {
		return handler.baseParser
				.parseVersionRequest(messageHeader, payloadStream)
				.then([this, &handler](styxe::Request::Version req) {
					UnversionedRequestVisiter visiter{messageHeader.tag, outputStream, handler, authenticationPolicy};
					return visiter(req);
				});
	}

	apsio::Result<SessionStateTransition> operator()(UnauthenticatedSessionHandler& handler) {
		return handler.parser()
				.parseRequest(messageHeader, payloadStream)
				.then([this, &handler](styxe::RequestMessage const& req) {
					return std::visit(UnauthenticatedRequestVisiter{messageHeader.tag, outputStream, handler, server.vfs()}, req);
				});
	}

	apsio::Result<SessionStateTransition> operator()(SessionProtocolHandler& handler) {
		return handler.parser()
				.parseRequest(messageHeader, payloadStream)
				.then([this, &handler](styxe::RequestMessage&& req) {
					return std::visit(StyxeRequestVisiter{messageHeader.tag, outputStream, handler, server.vfs()}, req);
				});
	}

	SessionStateHandler(styxe::MessageHeader header,
						ByteReader& input,
						ByteWriter& output,
						Server& s,
						std::shared_ptr<Auth::Policy> policy) noexcept
		: messageHeader{header}
		, payloadStream{input}
		, outputStream{output}
		, server{s}
		, authenticationPolicy{mv(policy)}
	{}

	styxe::MessageHeader messageHeader;
	ByteReader& payloadStream;
	ByteWriter& outputStream;

	Server& server;
	std::shared_ptr<Auth::Policy> authenticationPolicy;
};


struct MessageTypeNamer {

	StringView operator()(UnversionedSessionHandler const& handler) noexcept {
		return handler.baseParser.messageName(_type);
	}

	StringView operator()(UnauthenticatedSessionHandler const& handler) {
		return handler._parser.messageName(_type);
	}

	StringView operator()(SessionProtocolHandler const& handler) {
		return handler._parser.messageName(_type);
	}

	constexpr MessageTypeNamer(byte type) noexcept
		: _type{type}
	{}

	byte _type;
};


apsio::Result<styxe::MessageHeader>
AsyncSessionBase::parseMessageHeader(ByteReader& reader) const {
//	return std::visit(MessageHeaderHandler{reader},
	return std::visit([&reader](auto const& handler) { return handler.baseParser.parseMessageHeader(reader); },
					  _protocolHandler);
}


apsio::Result<void>
AsyncSessionBase::handleRequest(styxe::MessageHeader header, ByteReader& payloadReader, ByteWriter& responseWriter) {
	return std::visit(SessionStateHandler{header, payloadReader, responseWriter, server(), authPolicy()},
					  _protocolHandler)
			.then([this](SessionStateTransition&& response) {
				logHeader(response.responseHeader, "←");
				switchState(mv(response.newHandler));
			});
}


void
AsyncSessionBase::logError(asio::error_code const& ec) const {
	std::cerr << "Session error: " << ec << ". Session will be closed.\n";
}


void
AsyncSessionBase::logError(Error const& ec) const {
	std::cerr << "Session error: " << ec << ". Session will be closed.\n";
}


void
AsyncSessionBase::logHeader(styxe::MessageHeader const& header, char const* dirGlyph) const {
	std::clog << dirGlyph
			<< " [" << std::setw(5) << header.messageSize << "] "
			<< std::visit(MessageTypeNamer{header.type}, _protocolHandler) << ' '
			<< header.tag
			<< '\n';
}




/////

//	apsio::Result<SessionStateResult> operator()(styxe::Request::Version const& req) {
//		// TODO: Drop current session, close all opened fids, forget the user

//		auto& parser = sessionHandler.baseParser();
//		const auto minMessageSize = std::min(parser.maxMessageSize(), req.msize);

//		auto result = sessionHandler.setRequestParserVersion(req.version, minMessageSize);
//		if (!result)
//			return error(result.getError());

//		parser.maxNegotiatedMessageSize(minMessageSize);

//		StringView negotiatedVersion;

//		// If we can only server sub-version
//		if (req.version.startsWith(parser.PROTOCOL_VERSION))
//			negotiatedVersion = parser.PROTOCOL_VERSION;
//		else if (parser.PROTOCOL_VERSION.startsWith(req.version))
//			negotiatedVersion = req.version;
//		else
//			negotiatedVersion = styxe::kUnknownProtocolVersion;

//		return responseBuilder << styxe::Response::Version{negotiatedVersion, parser.maxNegotiatedMessageSize()};
//	}

//	apsio::Result<SessionStateResult> operator()(styxe::Request::Auth const& req) {
//		// TODO: Drop current session, close all opened fids, forget the user

//		auto res = sessionHandler.authHandler().authenticate(req.uname, req.aname);
//		if (!res) {
//			return responseBuilder << styxe::Response::Error{res.getError().toString().view()};
//		}


//		// TODO(abbyssoul): Implement auth middlewere
//		// Use req.afid to associate it with `auth` file, like:
//		// _openedNodes.emplace(req.fid, *res);
//		sessionHandler.user(*res);

//		return error("Auth not supported");
//	}


//	apsio::Result<SessionStateResult> operator()(styxe::Request::Attach const& req) {
//		auto maybeUser = sessionHandler.user();
//		if (!maybeUser) {  // No authenticated
//			return error(GenericError::ACCES, "attach");
//		}

//		auto maybeAttachingUser = sessionHandler.authHandler().lookup(req.uname);
//		if (!maybeAttachingUser) {
//			return error(GenericError::ACCES, "attach");
//		}

//		if (maybeUser != maybeAttachingUser) {
//			return error(GenericError::ACCES, "attach");
//		}

//		if (!req.aname.empty()) {
//			return error("Unexpected tree selected");

//			// TODO: Re-implement:
////            auto maybePath = Path::parse(req.aname);
////            if (!maybePath) {
////                return responseBuilder.error(maybePath.getError());
////            }

////            auto res = walk(attachementPoint, maybePath.unwrap(), nullptr);
////            if (!res) {
////                return responseBuilder.error(res.getError());
////            }

////            auto& attNode = res.unwrap();
////            if (!attNode->isWalkable()) {
////                return responseBuilder.error("File not found");
////            }

////            auto baseName = maybePath.unwrap().getBasename();
////            name.assign(baseName.data(), baseName.size());
////            attachementPoint = std::static_pointer_cast<DirectoryNode>(attNode);
//		}

//		auto& vfs = sessionHandler.vfs();
//		auto const& rootId = vfs.rootId();
//		sessionHandler.hashFid(req.fid, "", rootId);

//		return responseBuilder << styxe::Response::Attach{nodeToQid(*vfs.nodeById(rootId))};
//	}



//SessionProtocolHandler::~SessionProtocolHandler() {
	// Close outstanding files:
//    if (!_openedNodes.empty()) {
//        for (auto& node : _openedNodes) {
//            // TODO: Close nodes
//        }
//    }
//}



//Result<void, Error>
//SessionProtocolHandler::handleRequest(styxe::MessageHeader header, ByteReader& payloadStream, ByteWriter& outputStream) {
//	return _parser.parseRequest(header, payloadStream)
//		.then([this, header, &outputStream](styxe::RequestMessage&& req) {
//			auto& response = std::visit(StyxeRequestHandler{{outputStream, header.tag}, *this}, req);

//			logHeader(response.header(), "←");
////			auto responseHeader = response.header();
////			std::clog << "← [" << std::setw(5) << responseHeader.messageSize << "] " <<
////						 responseHeader.type << " " <<
////						 responseHeader.tag <<
////						 '\n';

//			return;
//		});
//}
