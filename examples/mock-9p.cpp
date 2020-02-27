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

#include <asio/signal_set.hpp>

#include <iostream>
#include <filesystem> // C++17 filesystem for file name handling
#include <map>

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>


using namespace Solace;
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


template <typename T>
int logAndExit(const char* message, T&& maybeResult) {
	if (maybeResult)
		return EXIT_SUCCESS;

	std::cerr << message
			  << ": "
			  << maybeResult.getError()
			  << ". terminating\n";

	return EXIT_FAILURE;
}


kasofs::User
getSystemUser() noexcept {
	return {getuid(), getgid()};
}


/**
 * VFS driver to serve *regular* system files.
 */
struct RegularFS final : public kasofs::Filesystem {
	using FileHandle = std::unique_ptr<FILE, decltype(&fclose)>;

	// Filesystem interface
	kasofs::FilePermissions defaultFilePermissions(NodeType) const noexcept override { return {0666}; }

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
	open(kasofs::INode& node, kasofs::Permissions) override {
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
	read(OpenFID streamId, kasofs::INode&, size_type, Solace::MutableMemoryView dest) override {
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
	write(OpenFID streamId, kasofs::INode&, size_type, Solace::MemoryView src) override {
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
	seek(OpenFID streamId, kasofs::INode&, size_type offset, SeekDirection direction) override {
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
	close(OpenFID streamId, kasofs::INode&) override {
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


apsio::Auth::Policy
configureAuthPolicy() {
	apsio::Auth::Policy::ACL acl{{"*", "*"}, std::make_unique<apsio::Auth::Strategy>()};
	acl.strategy->isRequired = false;

	auto maybePolicy = makeArrayOf<apsio::Auth::Policy::ACL>(mv(acl));
	// CHECK ERRORS

	return apsio::Auth::Policy{maybePolicy.moveResult()};
}


Solace::Result<void, Error>
mountFiles(kasofs::Vfs& vfs, kasofs::User user, int argc, char* const* argv) {
	auto maybeFsDriverId = vfs.registerFilesystem<RegularFS>();
	if (!maybeFsDriverId) {
		std::cerr << "[Internal]: Failed to register fs driver\n";
		return maybeFsDriverId.moveError();
	}

	auto fsId = *maybeFsDriverId;
	auto maybeFsDriver = vfs.findFs(fsId);
	if (!maybeFsDriver) {
		return makeError(GenericError::IO, "Failed to retrieve registered RegularFS driver.");
	}


	auto* fsDriver = static_cast<RegularFS*>(*maybeFsDriver);
	for (int i = 2; i < argc; ++i) {
		auto fileName = StringView{argv[i]};
		 fs::path filePath(argv[i]);
		 std::clog << "Mounting file: " << fileName;

		 if (!fs::exists(filePath)) {
			 std::clog << "[failure]\n";
			 std::cerr << "File " << filePath << " does not exist\n";
			 return makeError(GenericError::NOENT, "Faile does not exist");
		 }

		 if (!fs::is_regular_file(filePath)) {
			 std::clog << "[failure]\n";
			 std::cerr << "File " << filePath << " is not a regular file\n";
			 return makeError(GenericError::IO, "Not a regular file");
		 }

		 auto baseName = filePath.filename();
		 auto baseNameView = StringView{baseName.c_str()};
		 auto maybeNodeId = vfs.mknode(vfs.rootId(), baseNameView, fsId, 0, user);
		 if (!maybeNodeId) {
			 std::cerr << "[Internal]: Failed to register file\n";
			 return maybeNodeId.moveError();
		 }

		 auto boundName = vfs.nodeById(*maybeNodeId)
				 .map([fileName, fsDriver, &vfs, &maybeNodeId](kasofs::INode& node) {
					 fsDriver->bind(fileName, node);
					 vfs.updateNode(*maybeNodeId, node);
					 return 0;
				 });

		 if (!boundName) {
			 std::cerr << "[Internal]: Failed to bind filename: " << fileName << '\n';
			 return makeError(GenericError::IO, "Failed to bind a name");
		 }

		 std::clog << "[ok]\n";
	}

	return Ok();
}


Solace::Result<void, Error>
mountRamFS(kasofs::Vfs& vfs, kasofs::User user) {
	auto maybeRamFsDriverId = vfs.registerFilesystem<kasofs::RamFS>(4096);
	if (!maybeRamFsDriverId) {
		std::cerr << "[Internal]: Failed to register RAM fs driver\n";
		return maybeRamFsDriverId.moveError();
	}

	// Create a couple of fake RAM fs files:
	auto const ramFsId = *maybeRamFsDriverId;
	auto maybeRamNodeId_1 = vfs.mknode(vfs.rootId(), "mock-1.ram", ramFsId, kasofs::RamFS::kNodeType, user);
	if (!maybeRamNodeId_1) {
		std::cerr << "[Internal]: Failed to create tmp ram file\n";
		return maybeRamNodeId_1.moveError();
	}

	// Write content for a fake file of ram FS:
	auto writeResult = vfs.open(user, *maybeRamNodeId_1, kasofs::Permissions::WRITE)
			.then([](kasofs::File&& file) {
				auto str = StringLiteral{"Hello, this is a fake file content\n"};
				return file.write(str.view());
			});

	if (!writeResult) {
		std::cerr << "[Internal]: Failed to write fake ramFS file\n";
		return writeResult.moveError();
	}

	return Ok();
}


Solace::Result<kasofs::Vfs, Error>
makeVFS(int argc, char* const* argv) {
	auto currentUser = getSystemUser();
	auto maybeVfs = apsio::Result<kasofs::Vfs>{types::okTag, in_place, currentUser, kasofs::FilePermissions{0777}};
	auto& vfs = maybeVfs.unwrap();

	auto maybeMounted = mountFiles(vfs, currentUser, argc, argv)
			.then([&vfs, &currentUser]() { return mountRamFS(vfs, currentUser); });
	if (!maybeMounted)
		return maybeMounted.moveError();

	return maybeVfs;
}

apsio::Server::Config
configure() {
	apsio::Server::Config config{};
	config.authPolicy = configureAuthPolicy();

	return config;
}

}  // anonymous namespace


/**
 * A simple 9p server serving files specifed on a commad line.
 */
int main(int argc, char* const* argv) {
	if (argc < 2) {
		return usage(argv[0]);
	}

	// Attempt to parse a dialstring - address to listen for incoming connections for.
	auto maybeBind = tryParseDailString(argv[1]);
	if (!maybeBind) {
		return logAndExit("Error parsing dial-string", maybeBind);
	}

	asio::io_context iocontext;

	// Setup handlers of CTRL-C and kill signals
	asio::signal_set stopSignals{iocontext, SIGINT, SIGTERM};
	stopSignals.async_wait([&] (asio::error_code const& error, int signal_number) {
		if (error) {
			std::cerr << "Error waiting for a Signal: " << error.message() << std::endl;
			return;
		}

		std::clog << "Terminate signal " << signal_number << " received. stopping" << std::endl;
		iocontext.stop();
	});

	// Create a new vfs with mounted files
	auto maybeVfs = makeVFS(argc, argv);
	if (!maybeVfs) {
		return logAndExit("Create VFS", maybeVfs);
	}

	auto mockServer = apsio::SimpleServer{iocontext, *maybeVfs};
	auto maybeListener = mockServer.listen(*maybeBind, configure());
	if (!maybeListener) {
		return logAndExit("Error attempting to listen", maybeListener);
	}

	// Setup signale handlers of SIGHUP - makes server stop accepting new connections.
	asio::signal_set stopAcceptingSignals{iocontext, SIGHUP};
	stopAcceptingSignals.async_wait([&] (asio::error_code const& error, int signal_number) {
		if (error) {
			std::cerr << "Error waiting for a Signal: " << error.message() << std::endl;
			return;
		}

		std::clog << "Stop listening due to signal" << signal_number << std::endl;
		if (auto& listener = *maybeListener) {
			listener->terminate();
			listener.reset();
		}
	});

	std::clog << "Listening on: '" << *maybeBind << "'\n";
	iocontext.run();
	std::clog << "done\n";

	return EXIT_SUCCESS;
}
