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
#include "systemErrorDomain.hpp"
#include <solace/string.hpp>


#include <asio/error.hpp>


using namespace Solace;
using namespace apsio::impl;


AtomValue const apsio::impl::kCustomErrorCatergory        = atom("custom");
AtomValue const apsio::impl::kGenericErrorCatergory       = atom("generic");
AtomValue const apsio::impl::kSystemErrorCatergory        = atom("sys");
AtomValue const apsio::impl::kAsioSystemErrorCatergory    = atom("asio");

namespace /*anonimous*/ {

struct GenericErrorDomain : public ErrorDomain {

    StringView name() const noexcept override { return std::generic_category().name(); }

    String message(int code) const noexcept override {
        auto const str = std::generic_category().message(code);
		return makeString(str.data(), str.size()).unwrap();
    }
};


struct SystemErrorDomain : public ErrorDomain {

    StringView name() const noexcept override { return std::system_category().name(); }

    String message(int code) const noexcept override {
        auto const str = std::system_category().message(code);
		auto maybeString = makeString(str.data(), str.size());

		return maybeString
				? maybeString.moveResult()
				: String{};
    }
};

struct AsioSystemErrorDomain : public ErrorDomain {

    StringView name() const noexcept override { return asio::system_category().name(); }

    String message(int code) const noexcept override {
        auto const str = asio::system_category().message(code);
		return makeString(str.data(), str.size()).unwrap();
    }
};


const SystemErrorDomain systemErrorDomain{};
const GenericErrorDomain genericErrorDomain{};
const AsioSystemErrorDomain asioErrorDomain{};


auto const rego_generic = registerErrorDomain(kGenericErrorCatergory, genericErrorDomain);
auto const rego_system = registerErrorDomain(kSystemErrorCatergory, systemErrorDomain);
auto const rego_asio = registerErrorDomain(kAsioSystemErrorCatergory, asioErrorDomain);

}  // namespace


Error
apsio::impl::makeSystemError(std::error_code const& ec) noexcept {
    if (&ec.category() == &std::system_category())
		return Error{kSystemErrorCatergory, ec.value()};

    if (&ec.category() == &std::generic_category())
		return Error{kGenericErrorCatergory, ec.value()};

    if (&ec.category() == &asio::system_category())
		return Error{kAsioSystemErrorCatergory, ec.value()};

	return Error{kCustomErrorCatergory, ec.value()};
}
