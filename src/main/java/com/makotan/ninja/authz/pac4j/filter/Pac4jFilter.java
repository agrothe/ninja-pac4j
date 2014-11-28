/**
 * Copyright (C) 2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.makotan.ninja.authz.pac4j.filter;


import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.google.inject.Inject;
import com.makotan.ninja.authz.pac4j.NinjaWebContext;

import ninja.*;

import com.makotan.ninja.authz.pac4j.annotations.Logical;
import com.makotan.ninja.authz.pac4j.annotations.RequiresClient;
import com.makotan.ninja.authz.pac4j.annotations.RequiresPermission;
import com.makotan.ninja.authz.pac4j.annotations.RequiresRoles;
import com.makotan.ninja.authz.pac4j.configuration.ClientsFactory;
import com.makotan.ninja.authz.pac4j.util.UserUtils;

import ninja.servlet.ContextImpl;
import ninja.utils.NinjaProperties;

import org.pac4j.core.client.BaseClient;
import org.pac4j.core.client.Clients;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.exception.RequiresHttpAction;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.core.util.CommonHelper;

import javax.servlet.http.HttpServletRequest;

/**
 * @author kuroeda.makoto
 * @author muhammad.khairuddin
 *
 */
public class Pac4jFilter implements Filter {
//    protected static final Logger logger = LoggerFactory.getLogger(Pac4jFilter.class);
	
	public static final String PAC4J_LOGIN_PATH = "pac4j.auth.login_path";
	
	public static final String PAC4J_ERROR_REDIECT = "pac4j.auth.error_redirect";
	
	public final static String PAC4J_SUCCESS_REDIRECT = "pac4j.auth.success_redirect";
	
	public static final String PAC4J_CLIENT_NAME = "pac4j.client.client_name";
	
    public static final String ORIGINAL_REQUESTED_URL = "pac4j.originalRequestedUrl";
    
    @Inject
	protected Logger logger;
    
    @Inject
    NinjaProperties properties;

    @Inject
    ClientsFactory clientsFactory;

    @Inject
    UserUtils userUtils;
    
    private final Ninja ninja;
    
    @Inject
    public Pac4jFilter(Ninja ninja) {
        this.ninja = ninja;
    }

    public Result filter(FilterChain filterChain, Context context) {
    	/*if (context.getSession() == null) {
            // no session
            return ninja.getUnauthorizedResult(context);
        }*/
    	
        CommonProfile profile = userUtils.getProfile(context , CommonProfile.class);
        logger.log(Level.FINE, "profile : "+ profile);
        
        if (profile != null) {
        	// check roles and permission
        	boolean allowed = isAccessAllowed(profile, context);
        	if (!allowed) {
        		return ninja.getForbiddenResult(context);
        	}
            return filterChain.next(context);
        } else {
            WebContext web = new NinjaWebContext(context);
            if (ContextImpl.class.isInstance(context)) {
                ContextImpl impl = (ContextImpl) context;
                HttpServletRequest request = impl.getHttpServletRequest();

                String requestedUrl = request.getRequestURL().toString();
                String queryString = request.getQueryString();
                if (CommonHelper.isNotBlank(queryString)) {
                    requestedUrl += "?" + queryString;
                }
                logger.info("requestedUrl : "+requestedUrl);
                web.setSessionAttribute(ORIGINAL_REQUESTED_URL, requestedUrl);
            }
            
           
            String redirectUrl = properties.get(PAC4J_LOGIN_PATH);
            if (redirectUrl == null) {
            	Clients clients = clientsFactory.build();
            	String clientName=null;
                String annotatedClient = getClientNameFromAnnotation(context);
                if (annotatedClient != null) {
            		clientName = annotatedClient;
            	}
            	else {
                    clientName = web.getRequestParameter(clients.getClientNameParameter());
            	}
                
                if (clientName == null) {
                    clientName = properties.get(PAC4J_CLIENT_NAME);
                }
                
                BaseClient<Credentials, CommonProfile> bclient = (BaseClient<Credentials, CommonProfile>)clients.findClient(clientName);
                try {
                	redirectUrl = bclient.getRedirectAction(web, false, false).getLocation();
                	logger.info("URL: "+redirectUrl);
				} catch (RequiresHttpAction e1) {
					e1.printStackTrace();
				}
            }
            logger.info("redirectUrl :  "+redirectUrl);
            
            return Results.redirect(redirectUrl);
        }
    }
    
    protected String getClientNameFromAnnotation(Context context) {
    	Class clazz = context.getRoute().getControllerClass();
		Method method = context.getRoute().getControllerMethod();
		RequiresClient anno = null;
		if (method.isAnnotationPresent(RequiresClient.class)) {
			anno = method.getAnnotation(RequiresClient.class);
		}
		else if (clazz.isAnnotationPresent(RequiresClient.class)) {
			anno = (RequiresClient)clazz.getAnnotation(RequiresClient.class);
		}
		
		if (anno != null) {
			return anno.value();
		}
		
    	return null;
    }
    
    protected boolean isAccessAllowed(CommonProfile profile, Context context) {
    	if (hasRolesAccess(profile, context) && hasPermissionsAccess(profile, context)) {
    		return true;
    	}
    	return false;
    }
    
    /**
     * returns true if all roles are granted to the user or no <code>@RequiresRoles<code> annotation specified on the type or method. Returns false if no or not all roles are granted to the user.
     * 
     * @param the user profile
     * @param the web context
     * @return
     */
    protected boolean hasRolesAccess(CommonProfile profile, Context context) {
    	Class clazz = context.getRoute().getControllerClass();
		Method method = context.getRoute().getControllerMethod();
		
		RequiresRoles anno = null;
		if (method.isAnnotationPresent(RequiresRoles.class)) {
			anno = method.getAnnotation(RequiresRoles.class);
		}
		else if (clazz.isAnnotationPresent(RequiresRoles.class)) {
			anno = (RequiresRoles)clazz.getAnnotation(RequiresRoles.class);
		}
		
		if (anno != null) {
			logger.info("RequiresRoles annotation found. Validating roles...");
			if (anno.value().length > 1 && anno.logical().equals(Logical.OR)) {
				for (String role : anno.value()) {
					if (profile.getRoles().contains(role)) {
						return true;
					}
				}
			}
			
			return profile.getRoles().containsAll(Arrays.asList(anno.value()));
		}
		
    	return true;
    }
    
    /**
     * returns true if all permissions are granted to the user or no <code>@RequiresPermission<code> annotation specified on the type of method. Returns false if no or not all permissions are granted to the user.
     * 
     * @param profile the user profile
     * @param context the web context
     * @return true if this user contains all permissions specified on this method or type. 
     */
    protected boolean hasPermissionsAccess(CommonProfile profile, Context context) {
    	Class clazz = context.getRoute().getControllerClass();
		Method method = context.getRoute().getControllerMethod();
		RequiresPermission anno = null;
		if (method.isAnnotationPresent(RequiresPermission.class)) {
			anno = method.getAnnotation(RequiresPermission.class);
		}
		else if (clazz.isAnnotationPresent(RequiresPermission.class)) {
			anno = (RequiresPermission)clazz.getAnnotation(RequiresPermission.class);
		}
		
		if (anno != null) {
			logger.info("RequiresPermissions annotation found. Validating permissions...");
			if (anno.value().length > 1 && anno.logical().equals(Logical.OR)) {
				for (String permission : anno.value()) {
					if (profile.getPermissions().contains(permission)) {
						return true;
					}
				}
			}
			return profile.getPermissions().containsAll(Arrays.asList(anno.value()));
		}
		
    	return true;
    }
}
