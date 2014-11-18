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
package com.makotan.ninja.authz.pac4j.controllers;

import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;

import ninja.Context;
import ninja.Result;
import ninja.Results;
import ninja.servlet.util.Request;
import ninja.utils.NinjaProperties;

import org.pac4j.core.client.Client;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.exception.RequiresHttpAction;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.core.util.CommonHelper;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;


import com.google.inject.Inject;
import com.makotan.ninja.authz.pac4j.NinjaWebContext;
import com.makotan.ninja.authz.pac4j.configuration.ClientsFactory;
import com.makotan.ninja.authz.pac4j.filter.Pac4jFilter;
import com.makotan.ninja.authz.pac4j.util.UserUtils;

public class CallbackController {
    //private static final Logger logger = LoggerFactory.getLogger(CallbackController.class);

    private final String defaultUrl;

    //private final static String PAC4J_REDIRECT = "pac4j.default_redirect";
    
    @Inject
	protected Logger logger;
    
    @Inject
    ClientsFactory clientsFactory;

    @Inject
    UserUtils userUtils;

    @Inject
    public CallbackController(NinjaProperties properties) {
        defaultUrl = properties.getWithDefault(Pac4jFilter.PAC4J_SUCCESS_REDIRECT , "/");
    }


    public Result callback(Context context , @Request HttpServletRequest request) {
        NinjaWebContext nwContext = new NinjaWebContext(context);
        
		Client client = clientsFactory.build().findClient(nwContext);
        logger.info("client : " + client);
        
        Credentials credentials;
        try {
            credentials = client.getCredentials(nwContext);
        } catch (RequiresHttpAction requiresHttpAction) {
            logger.info("extra HTTP action required : " + requiresHttpAction);
            return nwContext.getResult();
        }
        
        logger.info("credentials : " + credentials);

        CommonProfile profile = (CommonProfile) client.getUserProfile(credentials, nwContext);
        logger.info("profile : "+ profile);
        if (profile != null) {
            // only save profile when it's not null
            userUtils.setProfile(context , profile);
        }
        
        String requestedUrl = (String) nwContext.getSessionAttribute(Pac4jFilter.ORIGINAL_REQUESTED_URL);
        logger.info("requestedUrl : "+ requestedUrl);
        if (CommonHelper.isNotBlank(requestedUrl)) {
            return Results.redirect(requestedUrl);
        } else {
            return Results.redirect(this.defaultUrl);
        }

    }
    
   
}
