/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.orquanet.aws.signature;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public final class HttpRequest implements Serializable{
	private static final long serialVersionUID = 6904523115498817088L;

	private String method;

    private String path;

    private String parameters;

    private Map<String, Collection<String>> headers;

    private String payload;

    private HttpRequest() {
    	headers = new HashMap<>();
    }
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

    public Map<String, Collection<String>> getHeaders() {
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

        public Builder headers(final Map<String, Collection<String>> headers) {
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
