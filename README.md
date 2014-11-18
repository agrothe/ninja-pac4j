Pac4j module for Ninja Framework
===========
ninja-pac4j is an authentication and authorization module that's implements Pac4j in Ninja Framework. 
The original source is from https://github.com/makotan/ninja-pac4j

This version supports:
ninja >= 4.0.0
pac4j 1.6.0


Getting Started
---------------

Setup
---------------
1) Clone this project into your local hard disk and run maven install.

2) Create new maven project or from your existing project add this dependency into your maven project's pom.xml 
    <dependency>
        <groupId>ninja.auth.pac4j</groupId>
        <artifactId>ninja-pac4j</artifactId>
        <version>1.0.0-SNAPSHOT</version>
    </dependency>

3) Set login path url in application.conf:
	pac4j.auth.login_path=/login
  
Set default client name (optional).

	pac4j.client.client_name=FormClient

The other way to define client is using @RequiresClient annotation at controller's type or method
	
	@FilterWith({Pac4jFilter.class})
	@RequiresClient("FormClient")
    public class ApplicationController {}
    
    or 
    
    @FilterWith({Pac4jFilter.class})
    @RequiresClient("FormClient")
    public Result index() {}
    
Set uri for successful login:

    pac4j.default_redirect=/


4) Create new class that implements ClientFactory and add your clients such as FormClient, FacebookClient, TwitterClient, etc. 
This client configuration is based on what you set in application.ini and @RequiresClient annotation

For example:
	
	import com.makotan.ninja.authz.pac4j.configuration.ClientFactory;
	
	public class MyClientFactory implements ClientFactory {
		
		public Clients build() {
			Clients clients = new Clients();
			
			final FacebookClient facebookClient = new FacebookClient("1558832927671715", "9a5c9f11f16f46c7a8b75648df311ea9");
        	facebookClient.setCallbackUrl("http://mywebsite.com/callback");
			
			...
			
			return clients;
		}
		
	}

5) Create class that implements ProfileAccess or you can use SampleProfileAccess

6) In conf/Module.java class, bind ClientsFactory and ProfileAccess interface to the class implementations respectively.

    bind(ClientsFactory.class).to(MyClientsFactory.class);
    bind(ProfileAccess.class).to(SampleProfileAccess.class);

7) Set route to the callback method in com.makotan.ninja.authz.pac4j.controllers.CallbackController.class using POST method

    router.POST().route("/callback").with(CallbackController.class , "callback");

8) To filter the url with use Pac4jFilter.class in FilterWith annotation.
	
	public class ApplicationController  {
    	
    	@FilterWith({Pac4jFilter.class})
    	public Result index() {...}
    	
    	...
    }

9) To add roles or/and permission to the Pac4jFilter, use com.makotan.ninja.authz.pac4j.annotations.RequiresRoles 
and com.makotan.ninja.authz.pac4j.annotations.RequiresPermissions
	
	@FilterWith({Pac4jFilter.class})
	@RequiresRoles(value={"ROLE_ADMIN","ROLE_USER", }, Logical.OR)
	@RequiresPermissions(value={"PERMISSION_VIEW", "PERMISSION_ADD"}, Logical.AND)
	public Result index() {...}



