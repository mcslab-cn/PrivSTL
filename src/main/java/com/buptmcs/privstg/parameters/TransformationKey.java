package com.buptmcs.privstg.parameters;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.HashMap;
import java.util.Map;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class TransformationKey extends SerializableParameters {
    private static final long serialVersionUID = 1L;

    private PairingParameters pairingParameters;

    private transient Element id;
    private final byte[] byteArrayId;

    private transient Element Dp;
    private final byte[] byteArrayDp;

    private transient Element D0p;
    private final byte[] byteArrayD0p;

    private transient Map<String, Element> D1sp;
    private final Map<String, byte[]> byteArrayD1sp;

    private transient Map<String, Element> D2sp;
    private final Map<String, byte[]> byteArrayD2sp;

    public TransformationKey(PairingParameters pairingParameters, Element id, Element Dp, Element D0p, Map<String, Element> D1sp, Map<String, Element> D2sp) {
        this.pairingParameters = pairingParameters;

        this.id = id;
        this.byteArrayId = this.id.toBytes();

        this.Dp = Dp;
        this.byteArrayDp = this.Dp.toBytes();

        this.D0p = D0p;
        this.byteArrayD0p = this.D0p.toBytes();

        this.D1sp = D1sp;
        this.D2sp = D2sp;

        this.byteArrayD1sp = new HashMap<>();
        this.byteArrayD2sp = new HashMap<>();

        for (String attribute : this.D1sp.keySet()) {
            this.byteArrayD1sp.put(attribute, this.D1sp.get(attribute).toBytes());
            this.byteArrayD2sp.put(attribute, this.D2sp.get(attribute).toBytes());
        }
    }

    public PairingParameters getPairingParameters() {
        return pairingParameters;
    }

    public Element getId() {
        return id;
    }

    public Element getDp() {
        return Dp;
    }

    public Element getD0p() {
        return D0p;
    }

    public Map<String, Element> getD1sp() {
        return D1sp;
    }

    public Map<String, Element> getD2sp() {
        return D2sp;
    }

    public String[] getAttributes() {
        return this.D1sp.keySet().toArray(new String[1]);
    }

    private void readObject(ObjectInputStream objectInputStream) throws ClassNotFoundException, IOException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.pairingParameters);
        this.id = pairing.getZr().newElementFromBytes(this.byteArrayId).getImmutable();
        this.Dp = pairing.getG1().newElementFromBytes(this.byteArrayDp).getImmutable();
        this.D0p = pairing.getG1().newElementFromBytes(this.byteArrayD0p).getImmutable();
        this.D1sp = new HashMap<>();
        this.D2sp = new HashMap<>();
        for (String attribute : this.byteArrayD1sp.keySet()) {
            this.D1sp.put(attribute, pairing.getG1().newElementFromBytes(this.byteArrayD1sp.get(attribute)).getImmutable());
            this.D2sp.put(attribute, pairing.getG1().newElementFromBytes(this.byteArrayD2sp.get(attribute)).getImmutable());
        }
    }
}
