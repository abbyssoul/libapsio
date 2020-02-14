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
#ifndef APSIO_TYPES_HPP
#define APSIO_TYPES_HPP

#include <solace/result.hpp>
#include <solace/error.hpp>

namespace apsio {

using Error = Solace::Error;

template<typename T>
using Result = Solace::Result<T, Error>;

}  // end of namespace apsio
#endif  // APSIO_TYPES_HPP
