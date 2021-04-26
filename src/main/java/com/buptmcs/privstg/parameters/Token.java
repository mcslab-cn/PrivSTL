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

public class Token extends SerializableParameters {

    private static final long serialVersionUID = 1L;

    private PairingParameters pairingParameters;

    private transient Element id;
    private final byte[] byteArrayId;

    private transient Map<String, Element> B1s;
    private final Map<String, byte[]> byteArrayB1s;

    private transient Map<String, Element> B2s;
    private final Map<String, byte[]> byteArrayB2s;

    private transient Map<String, Element> W0_1s;
    private final Map<String, byte[]> byteArrayW0_1s;

    private transient Map<String, Element> W0_2s;
    private final Map<String, byte[]> byteArrayW0_2s;

    private transient Map<String, Element> W1_1s;
    private final Map<String, byte[]> byteArrayW1_1s;

    private transient Map<String, Element> W1_2s;
    private final Map<String, byte[]> byteArrayW1_2s;

    private transient Element B0;
    private final byte[] byteArrayB0;

    private transient Element B1;
    private final byte[] byteArrayB1;

    private transient BigInteger V0;
    private final byte[] byteArrayV0;

    private transient BigInteger V1;
    private final byte[] byteArrayV1;

    private transient BigInteger V2;
    private final byte[] byteArrayV2;

    private transient BigInteger V3;
    private final byte[] byteArrayV3;

    private int[][] searchKeywordsCondition;

    private String[] keywords;


    public Token(PairingParameters pairingParameters, Element id,
                 Map<String, Element> B1s, Map<String, Element> B2s,
                 Map<String, Element> W0_1s, Map<String, Element> W0_2s, Map<String, Element> W1_1s, Map<String, Element> W1_2s,
                 Element B0, Element B1, BigInteger V0, BigInteger V1, BigInteger V2, BigInteger V3,
                 int[][] searchKeywordsCondition, String[] keywords) {
        this.pairingParameters = pairingParameters;

        this.id = id;
        this.byteArrayId = this.id.toBytes();

        this.B1s = B1s;
        this.B2s = B2s;

        this.byteArrayB1s = new HashMap<>();
        this.byteArrayB2s = new HashMap<>();

        for (String keyword : this.B1s.keySet()) {
            this.byteArrayB1s.put(keyword, this.B1s.get(keyword).toBytes());
            this.byteArrayB2s.put(keyword, this.B2s.get(keyword).toBytes());
        }

        this.W0_1s = W0_1s;
        this.W0_2s = W0_2s;

        this.byteArrayW0_1s = new HashMap<>();
        this.byteArrayW0_2s = new HashMap<>();

        for (String W0Encoding : this.W0_1s.keySet()) {
            this.byteArrayW0_1s.put(W0Encoding, this.W0_1s.get(W0Encoding).toBytes());
            this.byteArrayW0_2s.put(W0Encoding, this.W0_2s.get(W0Encoding).toBytes());
        }

        this.W1_1s = W1_1s;
        this.W1_2s = W1_2s;
        this.byteArrayW1_1s = new HashMap<>();
        this.byteArrayW1_2s = new HashMap<>();
        for (String W1Encoding : this.W1_1s.keySet()) {
            this.byteArrayW1_1s.put(W1Encoding, this.W1_1s.get(W1Encoding).toBytes());
            this.byteArrayW1_2s.put(W1Encoding, this.W1_2s.get(W1Encoding).toBytes());
        }

        this.B0 = B0;
        this.byteArrayB0 = this.B0.toBytes();

        this.B1 = B1;
        this.byteArrayB1 = this.B1.toBytes();

        this.V0 = V0;
        this.byteArrayV0 = V0.toByteArray();

        this.V1 = V1;
        this.byteArrayV1 = V1.toByteArray();

        this.V2 = V2;
        this.byteArrayV2 = V2.toByteArray();

        this.V3 = V3;
        this.byteArrayV3 = V3.toByteArray();

        this.searchKeywordsCondition = searchKeywordsCondition;
        this.keywords = keywords;
    }

    public PairingParameters getPairingParameters() {
        return pairingParameters;
    }

    public Element getId() {
        return id;
    }

    public Map<String, Element> getB1s() {
        return B1s;
    }

    public Map<String, Element> getB2s() {
        return B2s;
    }

    public Map<String, Element> getW0_1s() {
        return W0_1s;
    }

    public Map<String, Element> getW0_2s() {
        return W0_2s;
    }

    public Map<String, Element> getW1_1s() {
        return W1_1s;
    }

    public Map<String, Element> getW1_2s() {
        return W1_2s;
    }

    public Element getB0() {
        return B0;
    }

    public Element getB1() {
        return B1;
    }

    public BigInteger getV0() {
        return V0;
    }

    public BigInteger getV1() {
        return V1;
    }

    public BigInteger getV2() {
        return V2;
    }

    public BigInteger getV3() {
        return V3;
    }

    public int[][] getSearchKeywordsCondition() {
        return searchKeywordsCondition;
    }

    public String[] getKeywords() {
        return keywords;
    }


    private void readObject(ObjectInputStream objectInputStream) throws ClassNotFoundException, IOException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.pairingParameters);
        this.id = pairing.getZr().newElementFromBytes(this.byteArrayId).getImmutable();
        this.B1s = new HashMap<>();
        this.B2s = new HashMap<>();
        for (String keyword : this.byteArrayB1s.keySet()) {
            this.B1s.put(keyword, pairing.getG1().newElementFromBytes(this.byteArrayB1s.get(keyword)).getImmutable());
            this.B2s.put(keyword, pairing.getG1().newElementFromBytes(this.byteArrayB2s.get(keyword)).getImmutable());
        }
        this.W0_1s = new HashMap<>();
        this.W0_2s = new HashMap<>();
        for (String W0Encoding : this.byteArrayW0_1s.keySet()) {
            this.W0_1s.put(W0Encoding, pairing.getG1().newElementFromBytes(this.byteArrayW0_1s.get(W0Encoding)).getImmutable());
            this.W0_2s.put(W0Encoding, pairing.getG1().newElementFromBytes(this.byteArrayW0_2s.get(W0Encoding)).getImmutable());
        }
        this.W1_1s = new HashMap<>();
        this.W1_2s = new HashMap<>();
        for (String W1Encoding : this.byteArrayW1_1s.keySet()) {
            this.W1_1s.put(W1Encoding, pairing.getG1().newElementFromBytes(this.byteArrayW1_1s.get(W1Encoding)).getImmutable());
            this.W1_2s.put(W1Encoding, pairing.getG1().newElementFromBytes(this.byteArrayW1_2s.get(W1Encoding)).getImmutable());
        }

        this.B0 = pairing.getG1().newElementFromBytes(this.byteArrayB0).getImmutable();
        this.B1 = pairing.getG1().newElementFromBytes(this.byteArrayB1).getImmutable();

        this.V0 = new BigInteger(new String(byteArrayV0));
        this.V1 = new BigInteger(new String(byteArrayV1));
        this.V2 = new BigInteger(new String(byteArrayV2));
        this.V3 = new BigInteger(new String(byteArrayV3));

    }
}
