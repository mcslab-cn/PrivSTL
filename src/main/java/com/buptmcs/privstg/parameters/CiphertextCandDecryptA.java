package com.buptmcs.privstg.parameters;

import java.io.IOException;
import java.io.ObjectInputStream;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class CiphertextCandDecryptA extends SerializableParameters {
    private static final long serialVersionUID = 1L;

    private PairingParameters pairingParameters;

    private transient Element C;
    private final byte[] byteArrayC;

    private transient Element A;
    private final byte[] byteArrayA;

    public CiphertextCandDecryptA(PairingParameters pairingParameters, Element C, Element A) {

        this.pairingParameters = pairingParameters;

        this.C = C;
        this.byteArrayC = this.C.toBytes();

        this.A = A;
        this.byteArrayA = this.A.toBytes();
    }

    public Element getC() {
        return C;
    }

    public Element getA() {
        return A;
    }

    private void readObject(ObjectInputStream objectInputStream) throws ClassNotFoundException, IOException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.pairingParameters);
        this.C = pairing.getGT().newElementFromBytes(this.byteArrayC).getImmutable();
        this.A = pairing.getGT().newElementFromBytes(this.byteArrayA).getImmutable();
    }

}
