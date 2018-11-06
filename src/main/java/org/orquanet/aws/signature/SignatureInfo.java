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

public final class SignatureInfo implements Serializable{

	private static final long serialVersionUID = 4894453904235989396L;
	private String algorithm;
    private String signedHeaders;
    private String signature;

    public String getSignedHeaders() {
        return signedHeaders;
    }

    public String getSignature() {
        return signature;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public static Builder builder(){
        return new SignatureInfo.Builder();
    }

    public static final class Builder{

        private SignatureInfo signatureInfo;

        public Builder(){
            this.signatureInfo = new SignatureInfo();
        }

        public Builder algorithm(final String algorithm){
            this.signatureInfo.algorithm = algorithm;
            return this;
        }

        public Builder signedHeaders(final String signedHeaders){
            this.signatureInfo.signedHeaders = signedHeaders;
            return this;
        }

        public Builder signature(final String signature){
            this.signatureInfo.signature = signature;
            return this;
        }

        public SignatureInfo build() {
            return signatureInfo;
        }
    }
}
