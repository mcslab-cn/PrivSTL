package com.buptmcs.privstg.parameters;

import java.io.IOException;
import java.io.ObjectInputStream;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class MasterSecretKey extends SerializableParameters {
    private static final long serialVersionUID = 1L;

    private PairingParameters pairingParameters;

    private transient Element alpha;
    private final byte[] byteArrayAlpha;

    private transient Element beta;
    private final byte[] byteArrayBeta;

    private transient Element gama;
    private final byte[] byteArrayGama;

    private transient Element delta;
    private final byte[] byteArrayDelta;

    private transient Element fai;
    private final byte[] byteArrayFai;

    public MasterSecretKey(PairingParameters pairingParameters, Element alpha, Element beta, Element gama, Element delta, Element fai) {
        this.pairingParameters = pairingParameters;

        this.alpha = alpha;
        this.byteArrayAlpha = this.alpha.toBytes();

        this.beta = beta;
        this.byteArrayBeta = this.beta.toBytes();

        this.gama = gama;
        this.byteArrayGama = this.gama.toBytes();

        this.delta = delta;
        this.byteArrayDelta = this.delta.toBytes();

        this.fai = fai;
        this.byteArrayFai = this.fai.toBytes();
    }

    public PairingParameters getPairingParameters() {
        return pairingParameters;
    }

    public Element getAlpha() {
        return alpha;
    }

    public Element getBeta() {
        return beta;
    }

    public Element getGama() {
        return gama;
    }

    public Element getDelta() {
        return delta;
    }

    public Element getFai() {
        return fai;
    }

    private void readObject(ObjectInputStream objectInputStream) throws ClassNotFoundException, IOException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.pairingParameters);
        this.alpha = pairing.getZr().newElementFromBytes(this.byteArrayAlpha).getImmutable();
        this.beta = pairing.getZr().newElementFromBytes(this.byteArrayBeta).getImmutable();
        this.gama = pairing.getZr().newElementFromBytes(this.byteArrayGama).getImmutable();
        this.delta = pairing.getZr().newElementFromBytes(this.byteArrayDelta).getImmutable();
        this.fai = pairing.getZr().newElementFromBytes(this.byteArrayFai).getImmutable();
    }
}
