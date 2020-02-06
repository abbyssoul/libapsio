/*
*  Copyright (C) Ivan Ryabov - All Rights Reserved
*
*  Unauthorized copying of this file, via any medium is strictly prohibited.
*  Proprietary and confidential.
*
*  Written by Ivan Ryabov <abbyssoul@gmail.com>
*/
#pragma once
#ifndef APSIO_SYSTEMERRORDOMAIN_HPP
#define APSIO_SYSTEMERRORDOMAIN_HPP

#include "apsio/types.hpp"

// FIXME: Should be ASIO: error domain
#include <solace/errorDomain.hpp>
#include <solace/error.hpp>

#include <system_error>


namespace apsio::impl {


extern const Solace::AtomValue kCustomErrorCatergory;
extern const Solace::AtomValue kGenericErrorCatergory;
extern const Solace::AtomValue kSystemErrorCatergory;
extern const Solace::AtomValue kAsioSystemErrorCatergory;


[[nodiscard]]
Error makeSystemError(std::error_code const& ec) noexcept;

}  // namespace apsio::impl
#endif  // APSIO_SYSTEMERRORDOMAIN_HPP
