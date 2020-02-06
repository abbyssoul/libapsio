/*
*  Copyright (C) Ivan Ryabov - All Rights Reserved
*
*  Unauthorized copying of this file, via any medium is strictly prohibited.
*  Proprietary and confidential.
*
*  Written by Ivan Ryabov <abbyssoul@gmail.com>
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
