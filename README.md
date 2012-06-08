# BroadMask NPAPI-Plugin

A NPAPI-Plugin implementation of *BroadMask:* Privacy-Preserving communication in Online Social Networks using Broadcast Encryption and Symmetric Cryptography



## Building dependencies

In order to build this plugin, you first need to build or install the following libraries (Our CMake scripts search for these libraries under /usr/local/):

- GNU Multiprecision Library (GMPlib, http://gmplib.org)
- Pairing-Based Cryptography Library (LibPBC, http://crypto.stanford.edu/pbc)
- Crypto++ Library (http://www.cryptopp.com/)
- GnuPG Made Easy (GPGME, http://gnupg.org)
- CMake for FireBreath building process


On Mac OS X, you can use the [homebrew][homebrew] package manager. The following command installs all required libraries:

`brew install gmp pbc cryptopp gpgme`

On Ubuntu, this installs all libraries except libpbc (for which no package is currently available, build it according to http://crypto.stanford.edu/pbc/manual/ch01s01.html)

`apt-get install libgmp-dev libpbc-dev

## Building the NPAPI-Plugin

### Windows 

Compiling a FireBreath plugin on windows requires Visual Studio {2008, 2009, 2010}. Use the following command to *configure* the CMake build:

`firebreath\prep2010.cmd src build` (replace 2010 with your version of Visual Studio)

Then `cd` into the build directory and execute `cmake --build . --config MinSizeRel --target webpgPlugin`

After successful build the plugin can be found at `build\bin\projects\BroadMask\MinSizeRel\npwebpgPlugin.dll


### Mac OS X

On Mac OS X, execute the following script to configure the CMake build:

`firebreath/prepmac.sh src build -DCMAKE_BUILD_TYPE=MinSizeRel`
(Use -DCMAKE_OSX_ARCHITECTURES=i386 to build for 32-bit architecture)

Then `cd` into the build directory and execute `xcodebuild -target Broadmask`

After successful build, the plugin can be found at `build/bin/projects/Broadmask/MinSizeRel/Broadmask.so`

### Linux 

On Mac OS X, execute the following script to configure the CMake build:

`firebreath/prepmake.sh src build -DCMAKE_BUILD_TYPE=MinSizeRel`

Then `cd` into the build directory and execute `make Broadmask` to build the plugin

After successful build, the plugin can be found at `build/bin/projects/Broadmask/MinSizeRel/Broadmask.so`

[homebrew]: https://github.com/mxcl/homebrew

