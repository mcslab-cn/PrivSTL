package com.buptmcs.privstg.parameters;

public class CiphertextAndGT extends SerializableParameters {
    private static final long serialVersionUID = 1L;

    private Ciphertext ciphertext;
    private GT gt;

    public CiphertextAndGT(Ciphertext ciphertext, GT gt) {
        this.ciphertext = ciphertext;
        this.gt = gt;
    }

    public Ciphertext getCiphertext() {
        return ciphertext;
    }

    public GT getGt() {
        return gt;
    }

}
