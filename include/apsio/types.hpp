/*
*  Copyright (C) Ivan Ryabov - All Rights Reserved
*
*  Unauthorized copying of this file, via any medium is strictly prohibited.
*  Proprietary and confidential.
*
*  Written by Ivan Ryabov <abbyssoul@gmail.com>
*/
#pragma once
#ifndef APSIO_TYPES_HPP
#define APSIO_TYPES_HPP

#include <solace/result.hpp>
#include <solace/error.hpp>

namespace apsio {

using Error = Solace::Error;

template<typename T>
using Result = Solace::Result<T, Error>;

}  // end of namespace apsio
#endif // APSIO_TYPES_HPP
