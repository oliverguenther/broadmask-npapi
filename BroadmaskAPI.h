/**********************************************************\

  Auto-generated BroadmaskAPI.h

\**********************************************************/

#include <string>
#include <sstream>
#include <boost/weak_ptr.hpp>
#include "JSAPIAuto.h"
#include "BrowserHost.h"
#include "Broadmask.h"
#include "BCInstance.h"

#ifndef H_BroadmaskAPI
#define H_BroadmaskAPI

class BroadmaskAPI : public FB::JSAPIAuto
{
public:
    ////////////////////////////////////////////////////////////////////////////
    /// @fn BroadmaskAPI::BroadmaskAPI(const BroadmaskPtr& plugin, const FB::BrowserHostPtr host)
    ///
    /// @brief  Constructor for your JSAPI object.
    ///         You should register your methods, properties, and events
    ///         that should be accessible to Javascript from here.
    ///
    /// @see FB::JSAPIAuto::registerMethod
    /// @see FB::JSAPIAuto::registerProperty
    /// @see FB::JSAPIAuto::registerEvent
    ////////////////////////////////////////////////////////////////////////////
    BroadmaskAPI(const BroadmaskPtr& plugin, const FB::BrowserHostPtr& host) :
        m_plugin(plugin), m_host(host)
    {
        registerMethod("invokeInstance", make_method(this, &BroadmaskAPI::invokeInstance));
//        registerMethod("loadInstance", make_method(this, &BroadmaskAPI::loadInstance));
//        registerMethod("storeInstance", make_method(this, &BroadmaskAPI::loadInstance));
    }

    ///////////////////////////////////////////////////////////////////////////////
    /// @fn BroadmaskAPI::~BroadmaskAPI()
    ///
    /// @brief  Destructor.  Remember that this object will not be released until
    ///         the browser is done with it; this will almost definitely be after
    ///         the plugin is released.
    ///////////////////////////////////////////////////////////////////////////////
    virtual ~BroadmaskAPI() {};

    BroadmaskPtr getPlugin();
   
    void invokeInstance(std::string gid, int N);
    bool hasInstance(std::string gid);
    void loadInstance(std::string gid);
    
private:
    BroadmaskWeakPtr m_plugin;
    FB::BrowserHostPtr m_host;
    
    std::map<std::string, BCInstance> instances;

};

#endif // H_BroadmaskAPI

