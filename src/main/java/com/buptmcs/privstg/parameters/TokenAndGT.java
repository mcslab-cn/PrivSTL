package com.buptmcs.privstg.parameters;

public class TokenAndGT extends SerializableParameters {
    private static final long serialVersionUID = 1L;

    private Token token;
    private GT gt;

    public TokenAndGT(Token token, GT gt) {
        this.token = token;
        this.gt = gt;
    }

    public Token getToken() {
        return token;
    }

    public GT getGt() {
        return gt;
    }

}
