package com.example.fn;

import com.example.utils.ResourceServerConfig;

import java.util.LinkedHashMap;
import java.util.Map;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

public class AuthFunction {
	
    private static final String TOKEN_BEARER_PREFIX = "Bearer ";
    
    public static class Input {
        public String type;
        public String token;
    }

    public static class Result {
        // required
        public boolean active = false;
        public String principal;
        public String[] scope;
        public String expiresAt;

        // optional
        public String wwwAuthenticate;
        public String clientId;
        // optional context
        public Map<String, Object> context = new LinkedHashMap<String, Object>();
    }
    
    public Result handleRequest(Input input) {
    	Logger.getLogger(AuthFunction.class.getName()).log(Level.INFO, "############ oci-fn-test-auth-apigw START ############");
    	Logger.getLogger(AuthFunction.class.getName()).log(Level.INFO, "Test AuthFunction Input: "+input.toString());
        Result result = new Result();
        try {
	        if (input.token == null || !input.token.startsWith(TOKEN_BEARER_PREFIX)) {
	            result.active = false;
	            result.wwwAuthenticate = "Bearer error=\"missing_token\"";
	            Logger.getLogger(AuthFunction.class.getName()).log(Level.INFO, "oci-fn-test-auth-apigw ERROR=\"Missing Token\" END");
	            return result;
	        }
	
	        // remove "Bearer " prefix in the token string before processing
	        String jwtToken = input.token.substring(TOKEN_BEARER_PREFIX.length());
	        Logger.getLogger(AuthFunction.class.getName()).log(Level.INFO, "(Invoking Core AuthFn from Test AuthFn) JWT Token : " + jwtToken
	        		+ " will be validated by Fusion Host : "+ResourceServerConfig.FUSION_HOST_FOR_TOKEN_VALIDATION);
    		HttpClient client = HttpClients.custom().build();
    		HttpUriRequest request = RequestBuilder
    				.get()
    				.setUri(ResourceServerConfig.FUSION_APIGW_CORE_AUTH_ENDPOINT)
    				.setHeader(HttpHeaders.AUTHORIZATION, TOKEN_BEARER_PREFIX + ResourceServerConfig.FUSION_HOST_FOR_TOKEN_VALIDATION + 
    																			ResourceServerConfig.HOST_TOKEN_SPLITTER+jwtToken)
    				.build();
    		HttpResponse response = client.execute(request);
    		int statusCode = response.getStatusLine().getStatusCode();
    		String strResponse = EntityUtils.toString(response.getEntity());
    		Logger.getLogger(AuthFunction.class.getName()).log(Level.INFO, "Response => Status Code : "+statusCode);
    		if(statusCode == 200) {
    			result.active = true;
	            result.wwwAuthenticate = "Bearer error=\"valid_token\"";
	            /* Map<String, Object> cont = new LinkedHashMap<String, Object>();
	        	cont.put("Response", strResponse);
	        	result.context.putAll(cont); */
				Logger.getLogger(AuthFunction.class.getName()).log(Level.INFO, "Valid JWT Token");
    		} else {
    			Logger.getLogger(AuthFunction.class.getName()).log(Level.INFO, "Response : "+strResponse);
        		result.active = false;
	            result.wwwAuthenticate = "Bearer error=\"invalid_token\"";
	            Logger.getLogger(AuthFunction.class.getName()).log(Level.SEVERE, "Invaid JWT Token");
    		}
		} catch (Exception e) {
			e.printStackTrace();
			result.active = false;
            result.wwwAuthenticate = "Bearer error=\"invalid_token\", error_description=\""+e.getMessage()+"\"";
            Logger.getLogger(AuthFunction.class.getName()).log(Level.SEVERE, "ERROR =======> Bearer error=\"invalid_token\", error_description=\""+e.getMessage()+"\"");
		}
        Logger.getLogger(AuthFunction.class.getName()).log(Level.INFO, "############ oci-fn-test-auth-apigw END ############");
        return result;
    }
    
    public Result handleRequestForTesting(Input input) {
    	Result result = new Result();
    	result.active = true;
        result.wwwAuthenticate = "Bearer error=\"valid_token\"";
    	return result;
    }
}