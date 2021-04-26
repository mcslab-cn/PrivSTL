package com.buptmcs.privstg.geotree;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import com.buptmcs.privstg.parameters.Ciphertext;
import com.buptmcs.privstg.parameters.MasterSecretKey;
import com.buptmcs.privstg.parameters.PublicKey;
import com.buptmcs.privstg.parameters.SerializableParameters;
import com.buptmcs.util.GeneratorUtils;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class Node extends SerializableParameters {
    private static final long serialVersionUID = 1L;
    private static final String characterString = "0123456789bcdefghjkmnpqrstuvwxyz";
    private static final char[] character = characterString.toCharArray();

    private String id;
    private String geoHashString;
    private Node parent;
    private PairingParameters pairingParameters;
    private transient Element L0;
    private byte[] byteArrayL0;
    private transient Element L1;
    private byte[] byteArrayL1;
    private transient Element L2;
    private byte[] byteArrayL2;
    private transient Element L3;
    private byte[] byteArrayL3;
    private int level;
    private Set<Node> children = new HashSet<>();
    private Set<String> adjacentNodeId = new HashSet<>();
    private Set<Ciphertext> ciphertexts = new HashSet<>();

    public Node(String[] childrenGeoHash, PublicKey publicKey, MasterSecretKey masterSecretKey) {
        this.id = UUID.randomUUID().toString();
        this.geoHashString = "root";
        this.parent = this;
        this.pairingParameters = publicKey.getPairingParameters();
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        L0 = pairing.getG1().newOneElement().getImmutable();
        byteArrayL0 = L0.toBytes();
        L1 = pairing.getZr().newOneElement().getImmutable();
        byteArrayL1 = L1.toBytes();
        L2 = pairing.getZr().newOneElement().getImmutable();
        byteArrayL2 = L2.toBytes();
        L3 = pairing.getG1().newOneElement().getImmutable();
        byteArrayL3 = L3.toBytes();
        this.level = 3;
        for (String geoHashString : childrenGeoHash) {
            Node child = new Node(geoHashString, this, publicKey, masterSecretKey);
            children.add(child);
        }
    }

    public Node(String geoHashString, Node parent, PublicKey publicKey, MasterSecretKey masterSecretKey) {
        this.id = UUID.randomUUID().toString();
        this.geoHashString = geoHashString;
        this.parent = parent;
        this.pairingParameters = publicKey.getPairingParameters();
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        Element fai1 = pairing.getZr().newRandomElement().getImmutable();
        Element fai2 = pairing.getZr().newRandomElement().getImmutable();
        L0 = publicKey.getG().powZn(fai2).getImmutable();
        byteArrayL0 = L0.toBytes();
        L1 = masterSecretKey.getGama().mul(fai1).getImmutable();
        byteArrayL1 = L1.toBytes();
        L2 = masterSecretKey.getGama().mul(fai2).getImmutable();
        byteArrayL2 = L2.toBytes();
        byte[] hashGeoHash = GeneratorUtils.hash(geoHashString.getBytes());
        Element hGeoHash = pairing.getZr().newElementFromHash(hashGeoHash, 0, hashGeoHash.length).getImmutable();
        L3 = publicKey.getH1().powZn(fai1).mul(publicKey.getH().powZn(hGeoHash.mulZn(fai2))).getImmutable();
        byteArrayL3 = L3.toBytes();
        level = geoHashString.length();
        if (level < 6) {
            for (char c : character) {
                StringBuilder sb = new StringBuilder();
                sb.append(geoHashString).append(c);
                Node child = new Node(sb.toString(), this, publicKey, masterSecretKey);
                children.add(child);
            }
        }
    }

    private void readObject(ObjectInputStream objectInputStream) throws ClassNotFoundException, IOException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        L0 = pairing.getG1().newElementFromBytes(byteArrayL0).getImmutable();
        L1 = pairing.getZr().newElementFromBytes(byteArrayL1).getImmutable();
        L2 = pairing.getZr().newElementFromBytes(byteArrayL2).getImmutable();
        L3 = pairing.getG1().newElementFromBytes(byteArrayL3).getImmutable();
    }

    public String getId() {
        return id;
    }

    public String getGeoHashString() {
        return geoHashString;
    }

    public Node getParent() {
        return parent;
    }

    public PairingParameters getPairingParameters() {
        return pairingParameters;
    }


    public Element getL0() {
        return L0;
    }

    public Element getL1() {
        return L1;
    }

    public Element getL2() {
        return L2;
    }

    public Element getL3() {
        return L3;
    }

    public int getLevel() {
        return level;
    }

    public Set<Node> getChildren() {
        return children;
    }

    public Set<String> getAdjacentNodeId() {
        return adjacentNodeId;
    }

    public Set<Ciphertext> getCiphertexts() {
        return ciphertexts;
    }
}
