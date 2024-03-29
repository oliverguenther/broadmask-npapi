#/**********************************************************\ 
# Auto-generated X11 project definition file for the
# Broadmask project
#\**********************************************************/

# X11 template platform definition CMake file
# Included from ../CMakeLists.txt

# remember that the current source dir is the project root; this file is in X11/
file (GLOB PLATFORM RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    X11/[^.]*.cpp
    X11/[^.]*.h
    X11/[^.]*.cmake
    )

SOURCE_GROUP(X11 FILES ${PLATFORM})

# use this to add preprocessor definitions
add_definitions(
)

set (CMAKE_CXX_FLAGS "-Wl,-R,'$ORIGIN/lib'")
set (CMAKE_EXE_LINKER_FLAGS "-Wl,-R,'$ORIGIN/lib'")

set (SOURCES
    ${SOURCES}
    ${PLATFORM}
    )

add_x11_plugin(${PROJECT_NAME} SOURCES)

# add library dependencies here; leave ${PLUGIN_INTERNAL_DEPS} there unless you know what you're doing!
target_link_libraries(${PROJECT_NAME}
    ${PLUGIN_INTERNAL_DEPS}
	-I/usr/include
	-I/usr/local/include
	-lgmp
	-lpbc
	-lcryptopp
	-lgpgme
    )
