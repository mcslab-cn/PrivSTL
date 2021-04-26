package com.buptmcs.privstg.parameters;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;


import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class Ciphertext extends SerializableParameters {
    private static final long serialVersionUID = 1L;

    private PairingParameters pairingParameters;

    private transient Element C0;
    private final byte[] byteArrayC0;

    private transient Element C1;
    private final byte[] byteArrayC1;

    private transient Element C2;
    private final byte[] byteArrayC2;

    private transient Map<String, Element> C1s;
    private final Map<String, byte[]> byteArrayC1s;

    private transient Map<String, Element> C2s;
    private final Map<String, byte[]> byteArrayC2s;

    private transient Map<String, Element> E1s;
    private final Map<String, byte[]> byteArrayE1s;

    private transient Map<String, Element> E2s;
    private final Map<String, byte[]> byteArrayE2s;

    private transient Map<String, Element> T0_1s;
    private final Map<String, byte[]> byteArraysT0_1s;

    private transient Map<String, Element> T0_2s;
    private final Map<String, byte[]> byteArraysT0_2s;

    private transient Map<String, Element> T1_1s;
    private final Map<String, byte[]> byteArraysT1_1s;

    private transient Map<String, Element> T1_2s;
    private final Map<String, byte[]> byteArraysT1_2s;

    private transient BigInteger E0;
    private final byte[] byteArrayE0;

    private transient BigInteger E1;
    private final byte[] byteArrayE1;

    private transient BigInteger E2;
    private final byte[] byteArrayE2;

    private transient BigInteger E3;
    private final byte[] byteArrayE3;

    private int[][] accessPolicy;
    private String[] rhos;

    public Ciphertext(PairingParameters pairingParameters, Element C0, Element C1, Element C2,
                      Map<String, Element> C1s, Map<String, Element> C2s,
                      Map<String, Element> E1s, Map<String, Element> E2s,
                      Map<String, Element> T0_1s, Map<String, Element> T0_2s, Map<String, Element> T1_1s, Map<String, Element> T1_2s,
                      BigInteger E0, BigInteger E1, BigInteger E2, BigInteger E3, int[][] accessPolicy, String[] rhos) {
        this.pairingParameters = pairingParameters;

        this.C0 = C0;
        this.byteArrayC0 = this.C0.toBytes();

        this.C1 = C1;
        this.byteArrayC1 = this.C1.toBytes();

        this.C2 = C2;
        this.byteArrayC2 = this.C2.toBytes();

        this.C1s = C1s;
        this.C2s = C2s;

        this.byteArrayC1s = new HashMap<>();
        this.byteArrayC2s = new HashMap<>();

        for (String attribute : this.C1s.keySet()) {
            this.byteArrayC1s.put(attribute, this.C1s.get(attribute).toBytes());
            this.byteArrayC2s.put(attribute, this.C2s.get(attribute).toBytes());
        }

        this.E1s = E1s;
        this.E2s = E2s;

        this.byteArrayE1s = new HashMap<>();
        this.byteArrayE2s = new HashMap<>();

        for (String keyword : this.E1s.keySet()) {
            this.byteArrayE1s.put(keyword, this.E1s.get(keyword).toBytes());
            this.byteArrayE2s.put(keyword, this.E2s.get(keyword).toBytes());
        }

        this.T0_1s = T0_1s;
        this.T0_2s = T0_2s;
        this.byteArraysT0_1s = new HashMap<>();
        this.byteArraysT0_2s = new HashMap<>();
        for (String T0Encoding : this.T0_1s.keySet()) {
            this.byteArraysT0_1s.put(T0Encoding, this.T0_1s.get(T0Encoding).toBytes());
            this.byteArraysT0_2s.put(T0Encoding, this.T0_2s.get(T0Encoding).toBytes());
        }

        this.T1_1s = T1_1s;
        this.T1_2s = T1_2s;
        this.byteArraysT1_1s = new HashMap<>();
        this.byteArraysT1_2s = new HashMap<>();
        for (String T1Encoding : this.T1_1s.keySet()) {
            this.byteArraysT1_1s.put(T1Encoding, this.T1_1s.get(T1Encoding).toBytes());
            this.byteArraysT1_2s.put(T1Encoding, this.T1_2s.get(T1Encoding).toBytes());
        }

        this.E0 = E0;
        this.byteArrayE0 = E0.toByteArray();

        this.E1 = E1;
        this.byteArrayE1 = E1.toByteArray();

        this.E2 = E2;
        this.byteArrayE2 = E2.toByteArray();

        this.E3 = E3;
        this.byteArrayE3 = E3.toByteArray();

        this.accessPolicy = accessPolicy;
        this.rhos = rhos;
    }


    public PairingParameters getPairingParameters() {
        return pairingParameters;
    }

    public Element getC0() {
        return C0;
    }

    public Element getC1() {
        return C1;
    }

    public Element getC2() {
        return C2;
    }

    public Map<String, Element> getC1s() {
        return C1s;
    }

    public Map<String, Element> getC2s() {
        return C2s;
    }

    public Map<String, Element> getE1s() {
        return E1s;
    }

    public Map<String, Element> getE2s() {
        return E2s;
    }


    public Map<String, Element> getT0_1s() {
        return T0_1s;
    }

    public Map<String, Element> getT0_2s() {
        return T0_2s;
    }

    public Map<String, Element> getT1_1s() {
        return T1_1s;
    }

    public Map<String, Element> getT1_2s() {
        return T1_2s;
    }

    public BigInteger getE0() {
        return E0;
    }

    public BigInteger getE1() {
        return E1;
    }

    public BigInteger getE2() {
        return E2;
    }

    public BigInteger getE3() {
        return E3;
    }

    public int[][] getAccessPolicy() {
        return accessPolicy;
    }

    public String[] getRhos() {
        return rhos;
    }


    public String[] getCiphertextKeywords() {
        return this.E1s.keySet().toArray(new String[1]);
    }

    private void readObject(ObjectInputStream objectInputStream) throws ClassNotFoundException, IOException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.pairingParameters);
        this.C0 = pairing.getGT().newElementFromBytes(this.byteArrayC0).getImmutable();
        this.C1 = pairing.getG1().newElementFromBytes(this.byteArrayC1).getImmutable();
        this.C2 = pairing.getG1().newElementFromBytes(this.byteArrayC2).getImmutable();
        this.C1s = new HashMap<>();
        this.C2s = new HashMap<>();
        for (String attribute : this.byteArrayC1s.keySet()) {
            this.C1s.put(attribute, pairing.getG1().newElementFromBytes(this.byteArrayC1s.get(attribute)).getImmutable());
            this.C2s.put(attribute, pairing.getG1().newElementFromBytes(this.byteArrayC2s.get(attribute)).getImmutable());
        }
        this.E1s = new HashMap<>();
        this.E2s = new HashMap<>();
        for (String keyword : this.byteArrayE1s.keySet()) {
            this.E1s.put(keyword, pairing.getG1().newElementFromBytes(this.byteArrayE1s.get(keyword)).getImmutable());
            this.E2s.put(keyword, pairing.getG1().newElementFromBytes(this.byteArrayE2s.get(keyword)).getImmutable());
        }
        this.T0_1s = new HashMap<>();
        this.T0_2s = new HashMap<>();
        for (String T0Encoding : this.byteArraysT0_1s.keySet()) {
            this.T0_1s.put(T0Encoding, pairing.getG1().newElementFromBytes(this.byteArraysT0_1s.get(T0Encoding)).getImmutable());
            this.T0_2s.put(T0Encoding, pairing.getG1().newElementFromBytes(this.byteArraysT0_2s.get(T0Encoding)).getImmutable());
        }
        this.T1_1s = new HashMap<>();
        this.T1_2s = new HashMap<>();
        for (String T1Encoding : this.byteArraysT1_1s.keySet()) {
            this.T1_1s.put(T1Encoding, pairing.getG1().newElementFromBytes(this.byteArraysT1_1s.get(T1Encoding)).getImmutable());
            this.T1_2s.put(T1Encoding, pairing.getG1().newElementFromBytes(this.byteArraysT1_2s.get(T1Encoding)).getImmutable());
        }

        this.E0 = new BigInteger(new String(byteArrayE0));
        this.E1 = new BigInteger(new String(byteArrayE1));
        this.E2 = new BigInteger(new String(byteArrayE2));
        this.E3 = new BigInteger(new String(byteArrayE3));
    }
}
