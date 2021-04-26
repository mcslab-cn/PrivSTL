package com.buptmcs.privstg.parameters;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.HashMap;
import java.util.Map;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class SecretKey extends SerializableParameters {

    private static final long serialVersionUID = 1L;

    private PairingParameters pairingParameters;

    private transient Element D;
    private final byte[] byteArrayD;

    private transient Element D0;
    private final byte[] byteArrayD0;

    private transient Map<String, Element> D1s;
    private final Map<String, byte[]> byteArrayD1s;

    private transient Map<String, Element> D2s;
    private final Map<String, byte[]> byteArrayD2s;

    public SecretKey(PairingParameters pairingParameters, Element D, Element D0, Map<String, Element> D1s, Map<String, Element> D2s) {
        this.pairingParameters = pairingParameters;

        this.D = D;
        this.byteArrayD = this.D.toBytes();

        this.D0 = D0;
        this.byteArrayD0 = this.D0.toBytes();

        this.D1s = D1s;
        this.D2s = D2s;

        this.byteArrayD1s = new HashMap<>();
        this.byteArrayD2s = new HashMap<>();

        for (String attribute : this.D1s.keySet()) {
            this.byteArrayD1s.put(attribute, this.D1s.get(attribute).toBytes());
            this.byteArrayD2s.put(attribute, this.D2s.get(attribute).toBytes());
        }
    }

    public PairingParameters getPairingParameters() {
        return pairingParameters;
    }

    public Element getD() {
        return D;
    }

    public Element getD0() {
        return D0;
    }

    public Map<String, Element> getD1s() {
        return D1s;
    }

    public Map<String, Element> getD2s() {
        return D2s;
    }

    private void readObject(ObjectInputStream objectInputStream) throws ClassNotFoundException, IOException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.pairingParameters);
        this.D = pairing.getG1().newElementFromBytes(this.byteArrayD).getImmutable();
        this.D0 = pairing.getG1().newElementFromBytes(this.byteArrayD0).getImmutable();
        this.D1s = new HashMap<>();
        this.D2s = new HashMap<>();
        for (String attribute : this.byteArrayD1s.keySet()) {
            this.D1s.put(attribute, pairing.getG1().newElementFromBytes(this.byteArrayD1s.get(attribute)).getImmutable());
            this.D2s.put(attribute, pairing.getG1().newElementFromBytes(this.byteArrayD2s.get(attribute)).getImmutable());
        }
    }
}
