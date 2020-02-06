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

#include <solace/output_utils.hpp>
#include <dialstring/ostream.hpp>

#include <asio/signal_set.hpp>

#include <iostream>
#include <stdlib.h>


using namespace Solace;
using namespace styxe;


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

}  // namespace anonymous

/**
 * A simple example of decoding a 9P message from a file / stdin and printing it in a human readable format.
 */
int main(int argc, char* const* argv) {
	if (argc < 3)
		return usage(argv[0]);

	auto maybeBind = styxe::tryParseDailString(argv[1]);
	if (!maybeBind) {
		return logAndExit("Error parsing dial-string", maybeBind);
	}
	apsio::Server::Config config;

	auto vfs = kasofs::Vfs{getSystemUser(), kasofs::FilePermissions{0666}};

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
