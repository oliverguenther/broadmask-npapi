#/**********************************************************\ 
# Auto-generated Mac project definition file for the
# Broadmask project
#\**********************************************************/

# Mac template platform definition CMake file
# Included from ../CMakeLists.txt

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

include_directories( 
		"/usr/local/Broadmask/include"
        "/usr/local/include"
) 

link_directories(
		"/usr/local/Broadmask/lib"
		"/usr/local/lib"
)

set(PLIST "Mac/bundle_template/Info.plist")
set(STRINGS "Mac/bundle_template/InfoPlist.strings")
set(LOCALIZED "Mac/bundle_template/Localized.r")

add_mac_plugin(${PROJECT_NAME} ${PLIST} ${STRINGS} ${LOCALIZED} SOURCES)

# add library dependencies here; leave ${PLUGIN_INTERNAL_DEPS} there unless you know what you're doing!
target_link_libraries(${PROJECT_NAME}
    ${PLUGIN_INTERNAL_DEPS}
    -I/usr/include/
    -I/usr/local/include/
    -lgmp
    -lpbc
	-lcryptopp
	-lgpgme
    )

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
