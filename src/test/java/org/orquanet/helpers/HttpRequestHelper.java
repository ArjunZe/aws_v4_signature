package org.orquanet.helpers;

import org.orquanet.aws.signature.HttpRequest;

import java.util.HashMap;

public class HttpRequestHelper {

    public static  HttpRequest create() {
        HashMap<String, String> httpHeaders = new HashMap<>();
        httpHeaders.put("Host", " iam.amazonaws.com");
        httpHeaders.put("Content-Type", " application/x-www-form-urlencoded; charset=utf-8");

        httpHeaders.put("X-Amz-Date", " 20150830T123600Z");
        HttpRequest request = HttpRequest.builder().method("GET").path("/").
                parameters("Action=ListUsers&Version=2010-05-08").headers(httpHeaders).build();

        return request;

    }
}
