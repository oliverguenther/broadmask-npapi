#/**********************************************************\ 
# Auto-generated Mac project definition file for the
# Broadmask project
#\**********************************************************/

# Mac template platform definition CMake file
# Included from ../CMakeLists.txt

#Copy the specified lib to the plugin directory.
function(copyLibToFrameworks libPath pathToPlugin)
    ADD_CUSTOM_COMMAND(
        TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMAND mkdir -p ${pathToPlugin}/Contents/Frameworks
    )
    ADD_CUSTOM_COMMAND(
        TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMAND cp ${libPath} ${pathToPlugin}/Contents/Frameworks
    )
endfunction()
 
#Update the reference to the lib from the plugin.
function(updateReferencesToLib fromPath toPath targetLib)
    ADD_CUSTOM_COMMAND(
        TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMAND install_name_tool -change ${fromPath} ${toPath} ${targetLib}
    )
endfunction()
 
#Update the reference inside the target lib.
function(updateReferenceInLib toPath targetLib)
    ADD_CUSTOM_COMMAND(
        TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMAND install_name_tool -id ${toPath} ${targetLib}
    )
endfunction()
 
#Copy and update references for a library.
function(changeLoaderPath pathInBinary libFolder libName pathToPlugin)
    copyLibToFrameworks(${libFolder}/${libName} 
        ${pathToPlugin}
    )
    updateReferenceInLib(@loader_path/../Frameworks/${libName} 
        ${pathToPlugin}/Contents/Frameworks/${libName}
    )
    updateReferencesToLib(${pathInBinary} 
        @loader_path/../Frameworks/${libName} 
        ${pathToPlugin}/Contents/MacOS/${PROJECT_NAME}
    )
endfunction()


# remember that the current source dir is the project root; this file is in Mac/
file (GLOB PLATFORM RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    Mac/[^.]*.cpp
    Mac/[^.]*.h
    Mac/[^.]*.cmake
    )

# use this to add preprocessor definitions
add_definitions(
	-DCMAKE_OSX_ARCHITECTURES="x86_64"
)


SOURCE_GROUP(Mac FILES ${PLATFORM})

set (SOURCES
    ${SOURCES}
    ${PLATFORM}
    )


set (BROADMASK_PATH "/usr/local/Broadmask")
set (LIBRARY_PATH "${BROADMASK_PATH}/lib")

include_directories(
	"${BROADMASK_PATH}/include"
	"/usr/local/include" # boost ptr serialization
	)



#include_directories( 
#		"/usr/local/Broadmask/include"
#        "/usr/local/include"
#) 

#link_directories(
#		"/usr/local/Broadmask/lib"
#		"/usr/local/lib"
#)

set(PLIST "Mac/bundle_template/Info.plist")
set(STRINGS "Mac/bundle_template/InfoPlist.strings")
set(LOCALIZED "Mac/bundle_template/Localized.r")

add_mac_plugin(${PROJECT_NAME} ${PLIST} ${STRINGS} ${LOCALIZED} SOURCES)


# Library names
set (LGMP "libgmp.10.dylib")
set (LPBC "libpbc.1.dylib")
set (LASSUAN "libassuan.0.dylib")
set (LGPGERROR "libgpg-error.0.dylib")
set (LGPGME "libgpgme.11.dylib")

# add library dependencies here; leave ${PLUGIN_INTERNAL_DEPS} there unless you know what you're doing!
target_link_libraries(${PROJECT_NAME}
    ${PLUGIN_INTERNAL_DEPS}
	${LIBRARY_PATH}/${LGMP}
	${LIBRARY_PATH}/${LPBC}
	${LIBRARY_PATH}/libcryptopp.a
	${LIBRARY_PATH}/${LGPGME}
	${LIBRARY_PATH}/${LASSUAN}
	${LIBRARY_PATH}/${LGPGERROR}
	#-lgmp
	#-lpbc
	#-lcryptopp
	#-lgpgme
    )

# change rpath of included libraries to ../Frameworks/<lib>
set(PBIN "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_CFG_INTDIR}/${PROJECT_NAME}.plugin")
changeLoaderPath(${LIBRARY_PATH}/${LGMP} 
	${LIBRARY_PATH}
	${LGMP}
    ${PBIN}
)

changeLoaderPath(${LIBRARY_PATH}/${LPBC} 
	${LIBRARY_PATH}
    ${LPBC}
    ${PBIN}
)

changeLoaderPath(${LIBRARY_PATH}/${LGPGERROR}
	${LIBRARY_PATH}
	${LGPGERROR}
    ${PBIN}
)

changeLoaderPath(${LIBRARY_PATH}/${LASSUAN}
	${LIBRARY_PATH}
	${LASSUAN}
    ${PBIN}
)

changeLoaderPath(${LIBRARY_PATH}/${LGPGME}
	${LIBRARY_PATH}
	${LGPGME}
    ${PBIN}
)

# Change internal dependencies to the newly adjusted runtime paths

# GPG-ERROR dependency in assuan
updateReferencesToLib(${LIBRARY_PATH}/${LGPGERROR}
	@loader_path/../Frameworks/${LGPGERROR}
	${PBIN}/Contents/Frameworks/${LASSUAN}
	)


# GPG-ERROR dependency in GPGME
updateReferencesToLib(${LIBRARY_PATH}/${LGPGERROR}
	@loader_path/../Frameworks/${LGPGERROR}
	${PBIN}/Contents/Frameworks/${LGPGME}
	)

# ASSUAN dependency in GPGME
updateReferencesToLib(${LIBRARY_PATH}/${LASSUAN}
	@loader_path/../Frameworks/${LASSUAN}
	${PBIN}/Contents/Frameworks/${LGPGME}
	)

# GMP dependency in PBC
updateReferencesToLib(${LIBRARY_PATH}/${LGMP}
	@loader_path/../Frameworks/${LGMP}
	${PBIN}/Contents/Frameworks/${LPBC}
	)
