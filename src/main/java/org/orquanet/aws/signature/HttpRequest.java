package org.orquanet.aws.signature;

import java.util.Map;

public class HttpRequest {

    private String method;

    private String path;

    private String parameters;

    private Map<String, String> headers;

    private String payload;

    public String getMethod() {
        return method;
    }

    public String getPath() {
        return path;
    }

    public String getParameters() {
        return parameters;
    }

    public String getPayload() {return this.payload == null?"":this.payload;}

    public Map<String, String> getHeaders() {
        return this.headers;
    }

    public static Builder builder() {
        return new HttpRequest.Builder();
    }

    public static class Builder {
        private HttpRequest httpRequest = new HttpRequest();


        public Builder method(final String method) {
            this.httpRequest.method = method;
            return this;
        }

        public Builder path(final String path) {
            this.httpRequest.path = path;
            return this;
        }

        public Builder parameters(final String parameters) {
            this.httpRequest.parameters = parameters;
            return this;
        }

        public Builder headers(final Map<String, String> headers) {
            this.httpRequest.headers = headers;
            return this;
        }

        public Builder payload(final String payload){
            this.httpRequest.payload = payload;
            return this;
        }

        public HttpRequest build() {
            return httpRequest;
        }
    }
}
