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
