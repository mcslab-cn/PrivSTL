package com.buptmcs.privstg.parameters;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.interfaces.RSAPrivateKey;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class ServerBSecretKey extends SerializableParameters {
    private static final long serialVersionUID = 1L;

    private PairingParameters pairingParameters;

    private transient Element alphai;
    private final byte[] byteArrayAlphai;

    private RSAPrivateKey sk;

    public ServerBSecretKey(PairingParameters pairingParameters, Element alphai, RSAPrivateKey sk) {
        this.pairingParameters = pairingParameters;

        this.alphai = alphai;
        this.byteArrayAlphai = this.alphai.toBytes();

        this.sk = sk;
    }


    public PairingParameters getPairingParameters() {
        return pairingParameters;
    }

    public Element getAlphai() {
        return alphai;
    }

    public RSAPrivateKey getRSAPrivateKey2() {
        return sk;
    }


    private void readObject(ObjectInputStream objectInputStream) throws ClassNotFoundException, IOException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.pairingParameters);
        this.alphai = pairing.getZr().newElementFromBytes(this.byteArrayAlphai).getImmutable();

    }

}
