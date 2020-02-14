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
#include <apsio/simpleServer.hpp>

#include <kasofs/extras/ramfsDriver.hpp>
#include <solace/posixErrorDomain.hpp>
#include <solace/output_utils.hpp>
#include <dialstring/ostream.hpp>

#include <asio/signal_set.hpp>

#include <iostream>
#include <filesystem> // C++17
#include <map>

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>


using namespace Solace;
using namespace styxe;
namespace fs = std::filesystem;

namespace /*anonymous*/ {

/// Print app usage
int
usage(const char* progname) {
	std::cout << "Usage: " << progname
			  << " [-h]"
			  << " [dial]"
			  << " <FILEs>..."
			  << std::endl;

	std::cout << "Start a mock 9P server on a given address\n\n"
			  << "Options: \n"
			  << "  -h  Display help and exit\n"
			  << "\n"
			  << "Arguments: \n"
			  << "  [dial]   Bind-address to listen for connections\n"
			  << "  <Files>  List of files to serve\n"
			  << "\n"
			  << std::endl;

	return EXIT_FAILURE;
}


kasofs::User
getSystemUser() noexcept {
	return {getuid(), getgid()};
}


template <typename T>
int
logAndExit(const char* message, T&& maybeError) {
	if (maybeError)
		return EXIT_SUCCESS;

	std::cerr << message
			  << ": "
			  << maybeError.getError()
			  << ". terminating\n";

	return EXIT_FAILURE;
}




struct RegularFS final : public kasofs::Filesystem {
	using FileHandle = std::unique_ptr<FILE, decltype(&fclose)>;

	// Filesystem interface
	kasofs::FilePermissions defaultFilePermissions(NodeType type) const noexcept override { return {0666}; }

	kasofs::Result<kasofs::INode>
	createNode(NodeType type, kasofs::User owner, kasofs::FilePermissions perms) override {
		kasofs::INode node{type, owner, perms};
		node.vfsData = nextId();

		return Ok(std::move(node));
	}

	kasofs::Result<void> destroyNode(kasofs::INode& node) override {
		_nameBind.erase(node.vfsData);
		return Ok();
	}

	kasofs::Result<OpenFID>
	open(kasofs::INode& node, kasofs::Permissions op) override {
		auto boundNameIt = _nameBind.find(node.vfsData);
		if (boundNameIt == _nameBind.end()) {
			return makeError(GenericError::NOENT, "open: node name not bound");
		}

		auto file = FileHandle{fopen(boundNameIt->second.c_str(), "rw"), &fclose};
		if (!file)
			return makeErrno();

		auto fileId = nextOpenId();
		_openFiles.emplace(fileId, mv(file));

		return fileId;
	}

	kasofs::Result<size_type>
	read(OpenFID streamId, kasofs::INode& node, size_type offset, Solace::MutableMemoryView dest) override {
		auto it = _openFiles.find(streamId);
		if (it == _openFiles.end()) {
			return makeError(GenericError::IO, "read");
		}

		auto file = it->second.get();
		size_type bytesRead = fread(dest.dataAddress(), 1, dest.size(), file);
		if (ferror(file)) {
			return makeErrno("read");
		}

		return bytesRead;
	}


	kasofs::Result<size_type>
	write(OpenFID streamId, kasofs::INode& node, size_type offset, Solace::MemoryView src) override {
		auto it = _openFiles.find(streamId);
		if (it == _openFiles.end()) {
			return makeError(GenericError::IO, "write");
		}

		auto file = it->second.get();
		size_type bytesWritten = fwrite(src.dataAddress(), 1, src.size(), file);
		if (ferror(file)) {
			return makeErrno("write");
		}

		return bytesWritten;
	}


	kasofs::Result<size_type>
	seek(OpenFID streamId, kasofs::INode& node, size_type offset, SeekDirection direction) override {
		auto it = _openFiles.find(streamId);
		if (it == _openFiles.end()) {
			return makeError(GenericError::IO, "seek");
		}

		auto const origin = (direction == SeekDirection::FromStart)
				? SEEK_SET
				: (direction == SeekDirection::Relative) ? SEEK_CUR : SEEK_END;

		auto file = it->second.get();
		if (fseek(file, offset, origin)) {
			return makeErrno("seek");
		}

		size_type currentPos = ftell(file);
		return currentPos;
	}


	kasofs::Result<void>
	close(OpenFID streamId, kasofs::INode& node) override {
		_openFiles.erase(streamId);
		return Ok();
	}


	void bind(StringView filename, kasofs::INode& node) {
		auto it = _nameBind.emplace(node.vfsData, std::string{filename.data(), filename.size()});

		struct stat fileStats;
		if (stat(it.first->second.c_str(), &fileStats) == 0) {
			node.atime = fileStats.st_atim.tv_sec;
			node.mtime = fileStats.st_mtim.tv_sec;
			node.dataSize = fileStats.st_size;
			node.owner = kasofs::User{fileStats.st_uid, fileStats.st_gid};
//			node.permissions = fileStats.st_mode;
		}
	}


protected:

	kasofs::INode::VfsData		nextId() noexcept { return _idBase++; }
	OpenFID						nextOpenId() noexcept { return _openIdBase++; }

private:

	kasofs::INode::VfsData	_idBase{0};
	OpenFID					_openIdBase{0};

	std::unordered_map<NodeType, std::string>	_nameBind;
	std::unordered_map<OpenFID, FileHandle>		_openFiles;
};


}  // anonymous namespace


/**
 * A simple example of decoding a 9P message from a file / stdin and printing it in a human readable format.
 */
int main(int argc, char* const* argv) {
	if (argc < 2) {
		return usage(argv[0]);
	}

	auto maybeBind = styxe::tryParseDailString(argv[1]);
	if (!maybeBind) {
		return logAndExit("Error parsing dial-string", maybeBind);
	}

	apsio::Auth::Policy::ACL acl{{"*", "*"}, std::make_unique<apsio::Auth::Strategy>()};
	acl.strategy->isRequired = false;

	auto maybePolicy = makeArrayOf<apsio::Auth::Policy::ACL>(mv(acl));
	// CHECK ERRORS

	apsio::Auth::Policy policy{maybePolicy.moveResult()};

	apsio::Server::Config config{};
	config.authPolicy = mv(policy);

	auto currentUser = getSystemUser();
	auto vfs = kasofs::Vfs{currentUser, kasofs::FilePermissions{0777}};
	auto maybeFsDriverId = vfs.registerFilesystem<RegularFS>();
	if (!maybeFsDriverId) {
		std::cerr << "[Internal]: Failed to register fs driver: " << maybeFsDriverId.getError() << '\n';
		return EXIT_FAILURE;
	}

	auto maybeRamFsDriverId = vfs.registerFilesystem<kasofs::RamFS>(4096);
	if (!maybeRamFsDriverId) {
		std::cerr << "[Internal]: Failed to register RAM fs driver: " << maybeRamFsDriverId.getError() << '\n';
		return EXIT_FAILURE;
	}


	auto fsId = *maybeFsDriverId;
	auto maybeFsDriver = vfs.findFs(fsId);
	if (!maybeFsDriver)  {
		std::cerr << "[Internal]: Failed to get registered fs driver.\n";
		return EXIT_FAILURE;
	}


	auto* fsDriver = static_cast<RegularFS*>(*maybeFsDriver);
	for (int i = 2; i < argc; ++i) {
		auto fileName = StringView{argv[i]};
		 fs::path filePath(argv[i]);
		 std::clog << "Mounting file: " << fileName;

		 if (!fs::exists(filePath)) {
			 std::clog << "[failure]\n";
			 std::cerr << "File " << filePath << " does not exist\n";
			 return EXIT_FAILURE;
		 }

		 if (!fs::is_regular_file(filePath)) {
			 std::clog << "[failure]\n";
			 std::cerr << "File " << filePath << " is not a regular file\n";
			 return EXIT_FAILURE;
		 }


//		std::error_code ec; // For noexcept overload usage.
//		auto perms = fs::status(argv[i]).permissions();
//		if ((perms & fs::perms::owner_read) != fs::perms::none &&
//			(perms & fs::perms::group_read) != fs::perms::none &&
//			(perms & fs::perms::others_read) != fs::perms::none)
//		{

//		}

		auto maybeNodeId = vfs.mknode(vfs.rootId(), fileName, fsId, 0, currentUser);
		if (!maybeNodeId) {
			std::cerr << "[Internal]: Failed to register file: " << maybeNodeId.getError() << '\n';
			return EXIT_FAILURE;
		}

		auto boundName = vfs.nodeById(*maybeNodeId)
				.map([fileName, fsDriver, &vfs, &maybeNodeId](kasofs::INode& node) {
					fsDriver->bind(fileName, node);
					vfs.updateNode(*maybeNodeId, node);
					return 0;
				});

		if (!boundName) {
			std::cerr << "[Internal]: Failed to bind filename: " << fileName << '\n';
			return EXIT_FAILURE;
		}


		std::clog << "[ok]\n";
	}

	// Create a couple of fake RAM fs files:
	auto const ramFsId = *maybeRamFsDriverId;
	auto maybeRamNodeId_1 = vfs.mknode(vfs.rootId(), "mock-1.ram", ramFsId, 0, currentUser);
	if (!maybeRamNodeId_1) {
		std::cerr << "[Internal]: Failed to create tmp ram file: " << maybeRamNodeId_1.getError() << '\n';
		return EXIT_FAILURE;
	} else {
		auto writeResult = vfs.open(currentUser, *maybeRamNodeId_1, kasofs::Permissions::WRITE)
				.then([](kasofs::File&& file) {
					auto str = StringLiteral{"Hello, this is a fake file\n"};
					return file.write(str.view());
				});
		if (!writeResult) {
			std::cerr << "[Internal]: Failed to write test message: " << writeResult.getError() << '\n';
			return EXIT_FAILURE;
		}
	}

	asio::io_context iocontext;
	asio::signal_set stopSignals{iocontext, SIGINT, SIGTERM};
	stopSignals.async_wait([&] (asio::error_code const& error, int signal_number) {
		if (error) {
			std::cerr << "Error waiting for a Signal: " << error.message() << std::endl;
			return;
		}

		// TODO: It would be nice to know how many clients we dropped.
		std::clog << "Terminate signal " << signal_number << " received. stopping" << std::endl;
		iocontext.stop();
	});

	auto mockServer = apsio::SimpleServer{iocontext, vfs};
	auto maybeListener = mockServer.listen(*maybeBind, mv(config));
	if (!maybeListener) {
		return logAndExit("Error attempting to listen", maybeListener);
	}

	asio::signal_set stopAcceptingSignals{iocontext, SIGHUP};
	stopAcceptingSignals.async_wait([&] (asio::error_code const& error, int signal_number) {
		if (error) {
			std::cerr << "Error waiting for a Signal: " << error.message() << std::endl;
			return;
		}

		// TODO: It would be nice to know how many clients we dropped.
		std::clog << "Stop listening due to signal" << signal_number << std::endl;
		maybeListener.unwrap()->terminate();
		maybeListener.unwrap().reset();
	});

	std::clog << "Listening on: '" << *maybeBind << "'\n";
	iocontext.run();
	std::clog << "done\n";

	return EXIT_SUCCESS;
}
