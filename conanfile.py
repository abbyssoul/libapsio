#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Conan recipe package for libapsio
"""
from conans import CMake, ConanFile
from conans.errors import ConanInvalidConfiguration
from conans.model.version import Version


class LibapsioConan(ConanFile):
    name = "libapsio"
    license = "Apache-2.0"
    author = "Ivan Ryabov <abbyssoul@gmail.com>"
    url = "https://github.com/abbyssoul/%s.git" % name
    homepage = "https://github.com/abbyssoul/%s" % name
    description = "Async 9p server using modern C++"
    topics = ("Plan9", "server", "async", "Modern C++")
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options = "shared=False", "fPIC=True"
    generators = "cmake"

    scm = {
       "type": "git",
       "subfolder": name,
       "url": "auto",
       "revision": "auto"
    }
    requires = [
            "libstyxe/0.7.11@abbyssoul/stable",
            "libkasofs/0.3.14@abbyssoul/stable",
            "asio/1.13.0"]
    build_requires = "gtest/1.10.0"

    @property
    def _supported_cppstd(self):
        return ["17", "gnu17", "20", "gnu20"]

    @property
    def _source_subfolder(self):
        return self.name

    def config_options(self):
        compiler_version = Version(str(self.settings.compiler.version))

        if self.settings.os == "Windows":
            del self.options.fPIC
        # Exclude compilers that claims to support C++17 but do not in practice
        if (self.settings.compiler == "gcc" and compiler_version < "7") or \
           (self.settings.compiler == "clang" and compiler_version < "5") or \
           (self.settings.compiler == "apple-clang" and compiler_version < "9"):
          raise ConanInvalidConfiguration("This library requires C++17 or higher support standard. {} {} is not supported".format(self.settings.compiler, self.settings.compiler.version))
        if self.settings.compiler.cppstd and not self.settings.compiler.cppstd in self._supported_cppstd:
          raise ConanInvalidConfiguration("This library requires c++17 standard or higher. {} required".format(self.settings.compiler.cppstd))

    def _configure_cmake(self):
        cmake = CMake(self, parallel=True)
        cmake.definitions["PKG_CONFIG"] = "OFF"
        cmake.configure(source_folder=self._source_subfolder)
        return cmake

    def build(self):
        cmake = self._configure_cmake()
        cmake.build()

    def package(self):
        cmake = self._configure_cmake()
        cmake.install()
        self.copy(pattern="LICENSE", dst="licenses", src=self._source_subfolder)

    def package_info(self):
        self.cpp_info.libs = ["apsio"]
        if self.settings.os == "Linux":
            self.cpp_info.libs.append("m")

