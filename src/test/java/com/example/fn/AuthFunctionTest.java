/*
# oci-fn-auth-apigw version 1.0.
*/

package com.example.fn;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fnproject.fn.testing.*;
import org.junit.*;

import java.io.IOException;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.junit.Assert.*;

public class AuthFunctionTest {

    private static final ObjectMapper mapper = new ObjectMapper();

    public static class Result {
        // required
        public boolean active;
        public String principal;
        public String[] scope;
        public String expiresAt;

        // optional
        public String wwwAuthenticate;
        public String clientId;
        // optional context
        public Map<String,String> context;
    }

    private static String BEARER_TOKEN_PREFIX = "Bearer ";
    private static String INVALID_TOKEN = "TokenInvalid";
    private static String VALID_TOKEN = "TokenValid";
    /*
    private static String INPUT_FORMAT = "{\n" +
        "  \"type\":\"TOKEN\",\n" +
        "  \"token\": \"Bearer %s"+ ResourceServerConfig.TESTING_FUSION_HOST + ResourceServerConfig.HOST_TOKEN_SPLITTER +"%s\"\n" +
        "}";
	*/
    @Rule
    public final FnTestingRule testing = FnTestingRule.createDefault();

    @Test
    public void shouldReturnInactive() throws IOException {
        final String input = "{\n" +
            "  \"type\":\"TOKEN\",\n" +
            "  \"token\": \"" + BEARER_TOKEN_PREFIX + INVALID_TOKEN + "\"\n" +
            "}";
        Logger.getLogger(AuthFunctionTest.class.getName()).log(Level.INFO, "Invalid JWT Token : "+INVALID_TOKEN);
        testing.givenEvent().withBody(input).enqueue();
        testing.thenRun(AuthFunction.class, "handleRequest");

        FnResult fnResult = testing.getOnlyResult();

        Result result = mapper.readValue(fnResult.getBodyAsString(), Result.class);
        assertFalse(result.active);
        assertEquals("Bearer error=\"invalid_token\"", result.wwwAuthenticate);
        Logger.getLogger(AuthFunctionTest.class.getName()).log(Level.INFO, "Invalid JWT Token Response ==> "+fnResult.getBodyAsString());
    }

    @Test
    public void shouldReturnActive() throws Exception {
    	// String jwtToken = "eyJ4NXQiOiJXQWpiVXdfc0lDWjRPM3EySjZJb1g5d3VvZlUiLCJraWQiOiJ0cnVzdHNlcnZpY2UiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJPSUEuSU5URUdSQVRJT04iLCJpc3MiOiJ3d3cub3JhY2xlLmNvbSIsImV4cCI6MTY1MzU0OTEzOSwicHJuIjoiT0lBLklOVEVHUkFUSU9OIiwiaWF0IjoxNjUzNTM0NzM5fQ.dyGJs4m3f1aL_AS76pt5LxKg2xegguECbmYA1Bfy3z-mJt5zPwhOARvT62d4lTBFbSBQOl6ktDySrfVX5sPAG60LbXtHu36eeF2gl_YFZMd0RDgM2qTirVb6kq3QOSkKKIW36C7SMPf8pa-cEkO-5UTTZc_QMD3agOjADfmftrFUISAkqN75HA0FctZ4ExhKHVtzeCgqgIAr_QAcjH3QPdXf9ULOuJG3kzDV2orjVnepF-T1LdjPhGWQNBljykyVk9Xa0LVU-ZzkWhetR8JkYM1uxMuziIhA_1iIGrG-JmK0dlLCLDtSBPyYqo2KVC0VQ4CtDR0kxIc2IwyX5OKzDw";
    	String jwtToken = VALID_TOKEN;
        Logger.getLogger(AuthFunctionTest.class.getName()).log(Level.INFO, "Valid JWT Token : "+jwtToken);

        final String input = "{\n" +
                "  \"type\":\"TOKEN\",\n" +
                "  \"token\": \"" + BEARER_TOKEN_PREFIX + jwtToken + "\"\n" +
                "}";
        // final String input = String.format(INPUT_FORMAT, json);

        testing.givenEvent().withBody(input).enqueue();
        // testing.thenRun(AuthFunction.class, "handleRequest"); // Uncomment valid JWT Token and then uncomment this line
        testing.thenRun(AuthFunction.class, "handleRequestForTesting");

        FnResult fnResult = testing.getOnlyResult();

        Result result = mapper.readValue(fnResult.getBodyAsString(), Result.class);
        assertTrue(result.active);
        Logger.getLogger(AuthFunctionTest.class.getName()).log(Level.INFO, "Valid JWT Token Response ==> "+fnResult.getBodyAsString());
    }
}