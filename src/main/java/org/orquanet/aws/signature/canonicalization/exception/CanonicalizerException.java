package org.orquanet.aws.signature.canonicalization.exception;

public class CanonicalizerException extends RuntimeException {

    private static final long serialVersionUID = -5700478412668185014L;


	public CanonicalizerException() {
        super();
    }

    public CanonicalizerException(String s) {
        super(s);
    }

    public CanonicalizerException(Throwable throwable) {
        super(throwable);
    }

    public CanonicalizerException(String s, Throwable throwable) {
        super(s, throwable);
    }


    protected CanonicalizerException(String s, Throwable throwable, boolean b, boolean b1) {
        super(s, throwable, b, b1);
    }



}
