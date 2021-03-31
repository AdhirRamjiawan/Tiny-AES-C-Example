# CMakeList.txt : CMake project for LearnTinyAes, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

project ("LearnTinyAes")

# Add source to this project's executable.
add_executable (LearnTinyAes "LearnTinyAes.cpp" "LearnTinyAes.h")

# TODO: Add tests and install targets if needed.


target_link_libraries(LearnTinyAes LINK_PUBLIC "C:\\users\\adhir\\libs\\tiny-eas\\aes.a")
include_directories(LearnTinyAes "C:\\users\\adhir\\libs\\tiny-eas")