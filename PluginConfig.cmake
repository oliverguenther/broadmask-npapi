#/**********************************************************\ 
#
# Auto-Generated Plugin Configuration file
# for Broadmask
#
#\**********************************************************/

set(PLUGIN_NAME "Broadmask")
set(PLUGIN_PREFIX "BRO")
set(COMPANY_NAME "oliverguenther")

# ActiveX constants:
set(FBTYPELIB_NAME BroadmaskLib)
set(FBTYPELIB_DESC "Broadmask 1.0 Type Library")
set(IFBControl_DESC "Broadmask Control Interface")
set(FBControl_DESC "Broadmask Control Class")
set(IFBComJavascriptObject_DESC "Broadmask IComJavascriptObject Interface")
set(FBComJavascriptObject_DESC "Broadmask ComJavascriptObject Class")
set(IFBComEventSource_DESC "Broadmask IFBComEventSource Interface")
set(AXVERSION_NUM "1")

# NOTE: THESE GUIDS *MUST* BE UNIQUE TO YOUR PLUGIN/ACTIVEX CONTROL!  YES, ALL OF THEM!
set(FBTYPELIB_GUID 70db6395-e42a-5ddd-9342-df4ad39877e0)
set(IFBControl_GUID f71fcff8-4584-5094-887b-a679359b4da1)
set(FBControl_GUID f892ac63-7ad0-539e-a776-b241be7ba931)
set(IFBComJavascriptObject_GUID ea175718-17fd-5127-a8e4-89d8ce2ca7df)
set(FBComJavascriptObject_GUID 32705cbe-b891-5eb1-8986-9cd9cb60f0a6)
set(IFBComEventSource_GUID a36d0267-fa79-51d4-894a-641b54ddbd24)

# these are the pieces that are relevant to using it from Javascript
set(ACTIVEX_PROGID "oliverguenther.Broadmask")
set(MOZILLA_PLUGINID "oliverguenther.de/Broadmask")

# strings
set(FBSTRING_CompanyName "oliverguenther")
set(FBSTRING_FileDescription "Content Hiding in Online Social Networks using Broadcast Encryption")
set(FBSTRING_PLUGIN_VERSION "1.0.0.0")
set(FBSTRING_LegalCopyright "Copyright 2012 oliverguenther")
set(FBSTRING_PluginFileName "np${PLUGIN_NAME}.dll")
set(FBSTRING_ProductName "Broadmask")
set(FBSTRING_FileExtents "")
set(FBSTRING_PluginName "Broadmask")
set(FBSTRING_MIMEType "application/x-broadmask")

# Uncomment this next line if you're not planning on your plugin doing
# any drawing:

set (FB_GUI_DISABLED 1)

# Mac plugin settings. If your plugin does not draw, set these all to 0
set(FBMAC_USE_QUICKDRAW 0)
set(FBMAC_USE_CARBON 0)
set(FBMAC_USE_COCOA 0)
set(FBMAC_USE_COREGRAPHICS 0)
set(FBMAC_USE_COREANIMATION 0)
set(FBMAC_USE_INVALIDATINGCOREANIMATION 0)

# If you want to register per-machine on Windows, uncomment this line
#set (FB_ATLREG_MACHINEWIDE 1)

add_boost_library(filesystem)
add_boost_library(serialization)
add_boost_library(thread)
add_firebreath_library(jsoncpp)
