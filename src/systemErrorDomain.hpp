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
#ifndef APSIO_SRC_SYSTEMERRORDOMAIN_HPP
#define APSIO_SRC_SYSTEMERRORDOMAIN_HPP

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
#endif  // APSIO_SRC_SYSTEMERRORDOMAIN_HPP
