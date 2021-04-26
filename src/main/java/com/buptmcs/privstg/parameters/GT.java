package com.buptmcs.privstg.parameters;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.HashMap;
import java.util.Map;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class GT extends SerializableParameters {
    private static final long serialVersionUID = 1L;

    private PairingParameters pairingParameters;

    private transient Element K0;
    private final byte[] byteArrayK0;
    private transient Element K1;
    private final byte[] byteArrayK1;
    private transient Element K2;
    private final byte[] byteArrayK2;

    private transient Map<Integer, Element> Ks;
    private final Map<Integer, byte[]> byteArrayKs;

    public GT(PairingParameters pairingParameters, Element K0, Element K1, Element K2, Map<Integer, Element> Ks) {
        this.pairingParameters = pairingParameters;
        this.K0 = K0;
        this.byteArrayK0 = K0.toBytes();
        this.K1 = K1;
        this.byteArrayK1 = K1.toBytes();
        this.K2 = K2;
        this.byteArrayK2 = K2.toBytes();
        this.Ks = Ks;
        this.byteArrayKs = new HashMap<>();
        for (Integer i : Ks.keySet()) {
            this.byteArrayKs.put(i, Ks.get(i).toBytes());
        }
    }

    public PairingParameters getPairingParameters() {
        return pairingParameters;
    }

    public Element getK0() {
        return K0;
    }

    public Element getK1() {
        return K1;
    }

    public Element getK2() {
        return K2;
    }

    public Map<Integer, Element> getKs() {
        return Ks;
    }

    private void readObject(ObjectInputStream objectInputStream) throws ClassNotFoundException, IOException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        this.K0 = pairing.getG1().newElementFromBytes(byteArrayK0).getImmutable();
        this.K1 = pairing.getGT().newElementFromBytes(byteArrayK1).getImmutable();
        this.K2 = pairing.getGT().newElementFromBytes(byteArrayK2).getImmutable();
        this.Ks = new HashMap<>();
        for (Integer i : byteArrayKs.keySet()) {
            Ks.put(i, pairing.getG1().newElementFromBytes(byteArrayKs.get(i)).getImmutable());
        }
    }
}
