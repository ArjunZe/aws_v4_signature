package org.orquanet.helpers;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;

import org.orquanet.aws.signature.HttpRequest;

public class HttpRequestHelper {

    public static  HttpRequest create() {
        HashMap<String, Collection<String>> httpHeaders = new HashMap<>();
        httpHeaders.put("Host", Arrays.asList(" iam.amazonaws.com"));
        httpHeaders.put("Content-Type", Arrays.asList(" application/x-www-form-urlencoded; charset=utf-8"));

        httpHeaders.put("X-Amz-Date", Arrays.asList(" 20150830T123600Z"));
        HttpRequest request = HttpRequest.builder().method("GET").path("/").
                parameters("Action=ListUsers&Version=2010-05-08").headers(httpHeaders).build();

        return request;

    }
}
