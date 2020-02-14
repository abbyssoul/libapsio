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


// NOTE: The only reason to have it here - is to not emit vtable in each translation unit.
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
mapType(kasofs::INode const& inode) noexcept {
	if (kasofs::isDirectory(inode)) {
		return styxe::QidType::DIR;
	}

	// NOTE: We probably should halt at this point
	return styxe::QidType::FILE;
}

styxe::Qid
nodeToQid(kasofs::INode const& inode) noexcept {
	return styxe::Qid {
		inode.vfsData,
		inode.version,
		static_cast<byte>(mapType(inode))
	};
}


uint32
kasofsPermissionsTo9pMode(kasofs::INode const& inode) noexcept {
	uint32 mode = inode.permissions.value & 0777;

	if (kasofs::isDirectory(inode)) {
		mode |= static_cast<uint32>(styxe::DirMode::DIR);
		if (inode.permissions.user().can(kasofs::Permissions::READ)) { mode |= 0100; }
		if (inode.permissions.group().can(kasofs::Permissions::READ)) { mode |= 0010; }
		if (inode.permissions.others().can(kasofs::Permissions::READ)) { mode |= 0001; }
	}

	// TODO(abbyssoul): Set .u extended attributes

	// stats.mode = 0666;  // inode.permissions.value;
	//	| static_cast<uint32>(styxe::DirMode::READ) | static_cast<uint32>(styxe::DirMode::WRITE);

	return mode;
}

styxe::Qid
authQid(AuthFile const& SOLACE_UNUSED(strategy)) noexcept {
	return styxe::Qid{0, 0, static_cast<byte>(styxe::QidType::AUTH)};
}


styxe::Stat
nodeStats(kasofs::Vfs const& vfs, kasofs::Entry entry, kasofs::INode const& inode) {
	styxe::Stat stats;

	stats.qid = nodeToQid(inode);
	stats.type = inode.fsTypeId;       //!< server type (for kernel use)
	stats.dev = inode.nodeTypeId;        //!< server subtype (for kernel use)
	stats.mode = kasofsPermissionsTo9pMode(inode);
	stats.atime = inode.atime;
	stats.mtime = inode.mtime;
	stats.length = inode.dataSize;

	// FIX root name:
	stats.name = (entry.nodeId == vfs.rootId())
			? StringLiteral{"/"}
			: entry.name;

	stats.uid = StringLiteral{"soultaker"};
	stats.gid = StringLiteral{"soultaker"};
	/*
	stats.uid = inode.owner.uid;        //!< owner name
	stats.gid = inode.owner.gid;        //!< group name
	stats.muid = inode.owner.uid;       //!< name of the user who last modified the file
	*/

	// Size the stats struct
	stats.size = styxe::DirListingWriter::sizeStat(stats);

	return stats;
}



StringView selectProtocol(StringView requestedVersion) {
	// 9p version: The string must always begin with the two characters “9P”
	if (!requestedVersion.startsWith("9P")) {
		return styxe::kUnknownProtocolVersion;
	}

	// If we can only server sub-version
	/*
	if (req.version.startsWith(parser.PROTOCOL_VERSION)) {
		negotiatedVersion = parser.PROTOCOL_VERSION;
	} else if (parser.PROTOCOL_VERSION.startsWith(req.version))
		negotiatedVersion = req.version;
	}
	*/

	return styxe::kProtocolVersion;
}



struct SessionStateTransition {
	styxe::MessageHeader	responseHeader;
	SessionHandler			newHandler;
};


using MaybeTransition = apsio::Result<SessionStateTransition>;

apsio::Result<SessionStateTransition>
unsupportedMessage() /*noexcept */{
	return makeError(GenericError::PERM, "unsupported");
}


apsio::Result<AuthFile>
make_auth(StringView uname, Optional<uint32> uid, StringView resource, Auth::Strategy& strategy) {

	auto maybeName = makeString(uname);
	if (!maybeName)
		return maybeName.moveError();

	auto maybeResource = makeString(resource);
	if (!maybeResource)
		return maybeResource.moveError();

	return apsio::Result<AuthFile>{types::okTag, in_place,
				maybeName.moveResult(),
				mv(uid),
				maybeResource.moveResult(),
				strategy
			};
}

}  // anonymous namespace



Auth::Strategy&
UnauthenticatedSessionHandler::findAuthStrategy(StringView uname,
												   Optional<uint32> uid,
												   StringView resource) {
	return authPolicy()->findAuthStrategyFor({uname, resource});
}


apsio::Result<kasofs::User>
UnauthenticatedSessionHandler::authenticate(styxe::Fid afid, StringView name, Optional<uint32> uid, StringView res) {
	auto it = _fidToAuth.find(afid);
	if (it == _fidToAuth.end()) {
		return makeError(GenericError::IO, "authenticate");
	}

	auto& authFile = it->second;
	return authFile.authenticate(name, uid, res);
}


styxe::Qid
UnauthenticatedSessionHandler::beginAuth(styxe::Fid fid, AuthFile&& file) {
	auto it = _fidToAuth.try_emplace(fid, mv(file));
	auto& emplacedFile = it.first->second;

	return authQid(emplacedFile);
}


apsio::Result<AuthFile&>
UnauthenticatedSessionHandler::findAuthForFid(styxe::Fid fid) {
	auto it = _fidToAuth.find(fid);
	if (it == _fidToAuth.end())
		return makeError(GenericError::IO, "find");

	return Result<AuthFile&>{types::okTag, std::ref(it->second)};
}



struct BaseRequestVisiter {
#define DECLARE(T) \
	MaybeTransition operator()(T const&) { return unsupportedMessage(); }

	// Base 9P2000 protocol
	DECLARE(styxe::Request::Version)
	DECLARE(styxe::Request::Auth)
	DECLARE(styxe::Request::Flush)
	DECLARE(styxe::Request::Attach)
	DECLARE(styxe::Request::Walk)
	DECLARE(styxe::Request::Open)
	DECLARE(styxe::Request::Create)
	DECLARE(styxe::Request::Read)
	DECLARE(styxe::Request::Write)
	DECLARE(styxe::Request::Clunk)
	DECLARE(styxe::Request::Remove)
	DECLARE(styxe::Request::Stat)
	DECLARE(styxe::Request::WStat)

	// Handlers for 9P2000.U extention
	DECLARE(styxe::_9P2000U::Request::Auth)
	DECLARE(styxe::_9P2000U::Request::Attach)
	DECLARE(styxe::_9P2000U::Request::Create)
	DECLARE(styxe::_9P2000U::Request::WStat)

	// Handlers for 9P2000.E extention
	DECLARE(styxe::_9P2000E::Request::Session)
	DECLARE(styxe::_9P2000E::Request::ShortRead)
	DECLARE(styxe::_9P2000E::Request::ShortWrite)

	// Handlers for 9P2000.L extention
	DECLARE(styxe::_9P2000L::Request::StatFS)
	DECLARE(styxe::_9P2000L::Request::LOpen)
	DECLARE(styxe::_9P2000L::Request::LCreate)
	DECLARE(styxe::_9P2000L::Request::Symlink)
	DECLARE(styxe::_9P2000L::Request::MkNode)
	DECLARE(styxe::_9P2000L::Request::Rename)
	DECLARE(styxe::_9P2000L::Request::ReadLink)
	DECLARE(styxe::_9P2000L::Request::GetAttr)
	DECLARE(styxe::_9P2000L::Request::SetAttr)
	DECLARE(styxe::_9P2000L::Request::XAttrWalk)
	DECLARE(styxe::_9P2000L::Request::XAttrCreate)
	DECLARE(styxe::_9P2000L::Request::ReadDir)
	DECLARE(styxe::_9P2000L::Request::FSync)
	DECLARE(styxe::_9P2000L::Request::Lock)
	DECLARE(styxe::_9P2000L::Request::GetLock)
	DECLARE(styxe::_9P2000L::Request::Link)
	DECLARE(styxe::_9P2000L::Request::MkDir)
	DECLARE(styxe::_9P2000L::Request::RenameAt)
	DECLARE(styxe::_9P2000L::Request::UnlinkAt)

#undef DECLARE
};


struct UnversionedRequestVisiter : public BaseRequestVisiter {
	using BaseRequestVisiter::operator();

	MaybeTransition operator()(styxe::Request::Version const& req) {
		const auto minMessageSize = std::min(unversionedHandler.baseParser.maxMessageSize(), req.msize);

		auto negotiatedVersion = selectProtocol(req.version);

		// The version proposed is not supported - reply with 'UnknownProtocolVersion'
		if (styxe::kUnknownProtocolVersion.equals(negotiatedVersion)) {
			responseWriter << styxe::Response::Version{minMessageSize, negotiatedVersion};
			return responseOk();
		}

		auto versionedParser = styxe::createRequestParser(negotiatedVersion, minMessageSize);
		if (!versionedParser) {  // If failed to create a parser for the version, reply with 'UnknownProtocolVersion'
			responseWriter << styxe::Response::Version{minMessageSize, styxe::kUnknownProtocolVersion};
			return responseOk();
		}

		// Propose selected version and switch parser for a versioned one.
		responseWriter << styxe::Response::Version{minMessageSize, negotiatedVersion};
		return transitTo<UnauthenticatedSessionHandler>(versionedParser.moveResult(), authPolicy, mv(unversionedHandler));
	}

	MaybeTransition
	responseOk() noexcept {
		return SessionStateTransition{responseWriter.header(), mv(unversionedHandler)};
	}

	MaybeTransition
	transit(SessionHandler&& newSessionHandler) {
		return SessionStateTransition{responseWriter.header(), mv(newSessionHandler)};
	}

	template<typename NextState, typename...Args>
	MaybeTransition
	transitTo(Args&&...args) {
		return SessionStateTransition{responseWriter.header(), NextState{fwd<Args>(args)...}};
	}


	MaybeTransition
	error(SessionHandler&& newSessionHandler, StringView message) {
		responseWriter << styxe::Response::Error{message};
		return SessionStateTransition{responseWriter.header(), mv(newSessionHandler)};
	}

	MaybeTransition
	error(SessionHandler&& newSessionHandler, GenericError SOLACE_UNUSED(errCode), StringView message) {
		responseWriter << styxe::Response::Error{message};
		return SessionStateTransition{responseWriter.header(), mv(newSessionHandler)};
	}

	MaybeTransition
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


	UnversionedRequestVisiter(styxe::Tag responseTag,
							  ByteWriter& outputStream,
							  UnversionedSessionHandler& handler,
							  std::shared_ptr<Auth::Policy> auth)
		: unversionedHandler{handler}
		, authPolicy{mv(auth)}
		, responseWriter{outputStream, responseTag}
	{}

	UnversionedSessionHandler&		unversionedHandler;
	std::shared_ptr<Auth::Policy>	authPolicy;

	styxe::ResponseWriter			responseWriter;
};


struct UnauthenticatedRequestVisiter: public UnversionedRequestVisiter {

	using UnversionedRequestVisiter::operator();

	auto responseOk() { return transit(mv(_unauthenticatedHandler)); }
	auto responseNAK(StringView message) { return error(mv(_unauthenticatedHandler), message); }
	auto responseNAK(Error const& err) { return error(mv(_unauthenticatedHandler), err); }
	auto responseNAK(GenericError errCode, StringView message) {
		return error(mv(_unauthenticatedHandler), errCode, message);
	}

	MaybeTransition operator()(styxe::Request::Auth const& req) {
		return handleAuthRequest(req.afid, req.uname, none, req.aname);
	}

	MaybeTransition operator()(styxe::_9P2000U::Request::Auth const& req) {
		return handleAuthRequest(req.afid, req.uname, req.n_uname, req.aname);
	}

	MaybeTransition operator()(styxe::Request::Attach const& req) {
		return handleAttachRequest(req.fid, req.afid, req.uname, none, req.aname);
	}

	MaybeTransition operator()(styxe::_9P2000U::Request::Attach const& req) {
		return handleAttachRequest(req.fid, req.afid, req.uname, req.n_uname, req.aname);
	}


	// Note: It should be possible to read data from afid if selected authentication scheme supports it
	MaybeTransition operator()(styxe::Request::Read const& req) {
		auto maybeStrategy = _unauthenticatedHandler.findAuthForFid(req.fid);
		if (!maybeStrategy) {
			return responseNAK("Not attached fid");
		}
		// TODO(abbyssoul): not yet implemented
		// AuthStrategy& strategy = (*maybeStrategy);
		// responseWriter << styxe::Response::Read{*maybeBytesWritten};

		return unsupportedMessage();
	}


	// Note: Write call is used to write authentication details into provided afid
	MaybeTransition operator()(styxe::Request::Write const& req) {
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

protected:

	apsio::Result<SessionStateTransition>
	handleAuthRequest(styxe::Fid afid, StringView uname, Optional<uint32> uid, StringView aname) {
		// Prepare authentication mechanism for a new user idenfied as req.uname who wants to access resource req.aname

		// SEC: Note: do NOT open a new auth file for each auth requiest - as it can lean to DoS

		// TODO(abbyssoul): Even if user name is not valid - but auth is enabled - we should reply with ok, not an error
		auto& authStrategy = _unauthenticatedHandler.findAuthStrategy(uname, uid, aname);

		// 9PSEC: http://knusbaum.com/useful/rfc9p2000#P9SEC
		// If no auth is required - client must set its afid to NOFID on attach.
		if (!authStrategy.isRequired) {
			return responseNAK("Auth not required");
		}

		auto maybeAuthFile = make_auth(uname, uid, aname, authStrategy);
		if (!maybeAuthFile) {
			// ???? Internal server error! Close the session
			responseWriter << styxe::Response::Auth{};
			return responseOk();
		}

		auto authQid = _unauthenticatedHandler.beginAuth(afid, maybeAuthFile.moveResult());
		responseWriter << styxe::Response::Auth{authQid};  // authQid(authFile)};
		return responseOk();


		/*
		auto& authFile = *maybeAuthFile;
		if (!authFile.isAuthRequired()) {
			return responseNAK("Auth not required");
		}

		responseWriter << styxe::Response::Auth{authQid(authFile)};
		return responseOk();
		*/
	}


	apsio::Result<SessionStateTransition>
	handleAttachRequest(styxe::Fid fid, styxe::Fid afid, StringView uname, Optional<uint32> uid, StringView aname) {
		auto& authStrategy = _unauthenticatedHandler.findAuthStrategy(uname, uid, aname);


		auto user = (afid == styxe::kNoFID && !authStrategy.isRequired)
				? authStrategy.authenticate(uname, uid, aname, {})
				: _unauthenticatedHandler.authenticate(afid, uname, uid, aname);

		if (!user) {  // Authentication failed / incomplete
			return responseNAK(GenericError::ACCES, "attach");
		}

		// FIXME(abbyssoul): Current limitation - selecting named trees is not supported
		if (!aname.empty()) {
			return responseNAK(GenericError::ACCES, "attach: tree selection not supported");
		}

		auto const rootId = _vfs.rootId();
		responseWriter << styxe::Response::Attach{nodeToQid(*_vfs.nodeById(rootId))};

		// NOTE: We are passing literal not aname as hashFid won't copy strings :(
		return transitTo<SessionProtocolHandler>(*user, _vfs, fid, "", rootId, mv(_unauthenticatedHandler));
	}

private:

	UnauthenticatedSessionHandler&  _unauthenticatedHandler;
	kasofs::Vfs&					_vfs;
};


/**
 * Handler for Styxe Request messages
 * It is to be used as a visiter of styxe::Request variant
 */
struct StyxeRequestVisiter final : public UnauthenticatedRequestVisiter {

	using UnauthenticatedRequestVisiter::operator();

	auto responseOk() { return transit(mv(sessionHandler)); }
	auto responseNAK(StringView message) { return error(mv(sessionHandler), message); }
	auto responseNAK(Error const& err) { return error(mv(sessionHandler), err); }
	auto responseNAK(GenericError errCode, StringView message) { return error(mv(sessionHandler), errCode, message); }

	MaybeTransition operator()(styxe::Request::Walk const& req) {
		auto const maybeEntry = sessionHandler.entryByFid(req.fid);
		if (!maybeEntry) {
			return responseNAK("Not attached fid");
		}

		// TODO(abbyssoul): Make sure newFid is closed
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

		// TODO(abbyssoul): Support partial Walk response
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


	MaybeTransition operator()(styxe::Request::Open const& req) {
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

		auto maybeStats = i->second.stat();
		 if (!maybeStats) {
			return responseNAK(maybeStats.getError());
		 }

		responseWriter << styxe::Response::Open{nodeToQid(*maybeStats), 0};
		return responseOk();
	}


	MaybeTransition operator()(styxe::Request::Stat const& req) {
		auto maybeEntry = sessionHandler.entryByFid(req.fid);
		if (!maybeEntry) {
			return responseNAK("Not attached fid");
		}

		auto& vfs = sessionHandler.vfs();
		auto& entry = *maybeEntry;
		auto maybeFsNode = vfs.nodeById(entry.nodeId);
		if (!maybeFsNode)
			return responseNAK(GenericError::NOENT, "stat");

		auto nodeMeta = nodeStats(vfs, entry, *maybeFsNode);
		auto const datumSize = styxe::protocolSize(nodeMeta);
		responseWriter << styxe::Response::Stat{
								  narrow_cast<styxe::var_datum_size_type>(datumSize),
								  nodeMeta};
		return responseOk();
	}


	MaybeTransition operator()(styxe::Request::Flush const&) {
		// NOTE: In a single threaded environment - there are no concurrent operations
		responseWriter << styxe::Response::Flush{};
		return responseOk();
	}


	MaybeTransition operator()(styxe::Request::Clunk const& req) {
		auto maybeNode = sessionHandler.entryByFid(req.fid);
		if (!maybeNode) {
			return responseNAK("Not attached");
		}

		sessionHandler.removeOpened(req.fid);
		sessionHandler.removeEntryByFid(req.fid);

		responseWriter << styxe::Response::Clunk{};
		return responseOk();
	}


	MaybeTransition operator()(styxe::Request::Read const& req) {
		auto maybeOk = requiresNode(req.fid, "read");
		if (!maybeOk)
			return responseNAK(maybeOk.getError());

		auto& vfs = sessionHandler.vfs();
		auto [fidEntry, node, user] = *maybeOk;

		if (kasofs::isDirectory(node)) {
			auto dirWriter = styxe::DirListingWriter{responseWriter, req.count, req.offset};
			auto maybeIter = vfs.enumerateDirectory(user, fidEntry.nodeId);
			if (!maybeIter)
				return responseNAK(maybeIter.getError());

			for (auto entry : *maybeIter) {
				auto entryNode = vfs.nodeById(entry.nodeId);
				if (!entryNode) {
					return responseNAK(GenericError::IO, "read");
				}

				if (!dirWriter.encode(nodeStats(vfs, entry, *entryNode))) {
					break;
				}
			}

			return responseOk();
		}

		// Case of 'regular' a file:
		auto maybeOpenedFile = sessionHandler.findOpened(req.fid);
		if (!maybeOpenedFile)
			return responseNAK("not opened");

		auto& file = *(*maybeOpenedFile);
		auto maybeOffset = file.seekRead(req.offset, kasofs::Filesystem::SeekDirection::FromStart);
		if (!maybeOffset)
			return responseNAK(maybeOffset.getError());

		auto dataWriter = responseWriter << styxe::Response::Partial::Read{};
		MutableMemoryView dataDest = dataWriter.viewRemainder();
		auto maybeReader = file.read(dataDest.slice(0, req.count));
		if (!maybeReader)
			return responseNAK(maybeReader.getError());
		dataWriter.update(*maybeReader);

		return responseOk();
	}


	MaybeTransition operator()(styxe::Request::Write const& req) {
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


	apsio::Result<SessionStateTransition>
	operator()(styxe::Request::Create const& )  {
		return responseNAK("Not supported");
	}

	MaybeTransition operator()(styxe::Request::Remove const& ) {
		return responseNAK("Not supported");
	}

	MaybeTransition operator()(styxe::Request::WStat const& )  {
		return responseNAK("Not supported");
	}


	apsio::Result<std::tuple<kasofs::Entry, kasofs::INode, kasofs::User>>
	requiresNode(styxe::Fid fid, StringLiteral tag) {
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


	StyxeRequestVisiter(styxe::Tag tag, ByteWriter& outputStream, SessionProtocolHandler& handler, kasofs::Vfs& vfs)
		: UnauthenticatedRequestVisiter{tag, outputStream, handler, vfs}
		, sessionHandler{handler}
	{}


	SessionProtocolHandler&		sessionHandler;
};


struct SessionStateHandler {

	MaybeTransition operator()(UnversionedSessionHandler& handler) {
		return handler.baseParser
				.parseVersionRequest(messageHeader, payloadStream)
				.then([this, &handler](styxe::Request::Version req) {
					UnversionedRequestVisiter visiter{messageHeader.tag, outputStream, handler, authenticationPolicy};
					return visiter(req);
				});
	}

	MaybeTransition operator()(UnauthenticatedSessionHandler& handler) {
		return handler.parser()
				.parseRequest(messageHeader, payloadStream)
				.then([this, &handler](styxe::RequestMessage const& req) {
					return std::visit(UnauthenticatedRequestVisiter{messageHeader.tag, outputStream, handler, server.vfs()}, req);
				});
	}

	MaybeTransition operator()(SessionProtocolHandler& handler) {
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

	StringView operator()(UnversionedSessionHandler const&) noexcept {
		return styxe::messageTypeToString(_type);
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
