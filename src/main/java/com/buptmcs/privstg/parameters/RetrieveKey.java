package com.buptmcs.privstg.parameters;

import java.io.IOException;
import java.io.ObjectInputStream;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class RetrieveKey extends SerializableParameters {

    private static final long serialVersionUID = 1L;

    private PairingParameters pairingParameters;

    private transient Element tau;
    private final byte[] byteArrayTau;

    public RetrieveKey(PairingParameters pairingParameters, Element tau) {
        this.pairingParameters = pairingParameters;
        this.tau = tau;
        this.byteArrayTau = tau.toBytes();
    }

    public PairingParameters getPairingParameters() {
        return pairingParameters;
    }

    public Element getTau() {
        return tau;
    }

    private void readObject(ObjectInputStream objectInputStream) throws ClassNotFoundException, IOException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.pairingParameters);
        this.tau = pairing.getZr().newElementFromBytes(this.byteArrayTau).getImmutable();
    }
}
