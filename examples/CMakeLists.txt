# Build examples

# Example of using VFS as ram disk
set(EXAMPLE_APPFRAMEWORK_SOURCE_FILES mock-9p.cpp)
add_executable(mock-9p ${EXAMPLE_APPFRAMEWORK_SOURCE_FILES})
target_link_libraries(mock-9p PUBLIC ${PROJECT_NAME} ${CONAN_LIBS})


add_custom_target(examples
    DEPENDS mock-9p)
