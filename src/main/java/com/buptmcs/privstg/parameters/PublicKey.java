package com.buptmcs.privstg.parameters;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class PublicKey extends SerializableParameters{
	private static final long serialVersionUID = 1L;

	private PairingParameters pairingParameters;
	
	private transient Element g;
	private final byte[] byteArrayG;
	
	private transient Element g1;
	private final byte[] byteArrayG1;
	
	private transient Element g2;
	private final byte[] byteArrayG2;	
	
	private transient Element g3;
	private final byte[] byteArrayG3;
	
	private transient Element g4;
	private final byte[] byteArrayG4;
	
	private transient Element eghAlpha;
	private final byte[] byteArrayEghAlpha;
	
	private transient Element gBeta;
	private final byte[] byteArrayGBeta;
	
	private transient Element h;
	private final byte[] byteArrayH;
	
	private transient Element h1;
	private final byte[] byteArrayH1;
	
	private transient Element h2;
	private final byte[] byteArrayH2;
	
	private transient Element w1;
	private final byte[] byteArrayW1;
	
	private BigInteger N1;
	
	private BigInteger N2;
	
	private  RSAPublicKey pk1;
	private  RSAPublicKey pk2;
	
	private int maxBinaryTimeLength;
	
	public PublicKey(PairingParameters pairingParameters,Element g,Element h,Element eghAlpha,Element gBeta,Element g1,
			Element w1,Element g2,Element h1,Element h2,Element g3,Element g4, BigInteger N1, BigInteger N2, 
			RSAPublicKey pk1, RSAPublicKey pk2, int maxBinaryTimeLength) {
		
			this.pairingParameters = pairingParameters;
			
			this.g = g;
			this.byteArrayG = this.g.toBytes();
			
			this.g1 = g1;
			this.byteArrayG1 = this.g1.toBytes();
			
			this.g2 = g2;
			this.byteArrayG2 = this.g2.toBytes();
			
			this.g3 = g3;
			this.byteArrayG3 = this.g3.toBytes();
			
			this.g4 = g4;
			this.byteArrayG4 = this.g4.toBytes();
			
			this.eghAlpha = eghAlpha;
			this.byteArrayEghAlpha = this.eghAlpha.toBytes();
			
			this.gBeta = gBeta;
			this.byteArrayGBeta = this.gBeta.toBytes();
			
			this.h = h;
			this.byteArrayH = this.h.toBytes();
			
			this.h1 = h1;
			this.byteArrayH1 = this.h1.toBytes();
			
			this.h2 = h2;
			this.byteArrayH2 = this.h2.toBytes();
			
			this.w1 = w1;
			this.byteArrayW1 = this.w1.toBytes();
			
			this.N1=N1;
			
			this.N2=N2;
			
			this.pk1=pk1;
			this.pk2=pk2;
			
			this.maxBinaryTimeLength = maxBinaryTimeLength;
	}

	public PairingParameters getPairingParameters() {
		return pairingParameters;
	}

	public Element getG() {
		return g;
	}
	
	public Element getG1() {
		return g1;
	}
	
	public Element getG2() {
		return g2;
	}
	
	public Element getG3() {
		return g3;
	}
	
	public Element getG4() {
		return g4;
	}
	
	public Element getEghAlpha() {
		return eghAlpha;
	}

	public Element getgBeta() {
		return gBeta;
	}
	
	public Element getH() {
		return h;
	}
	
	public Element getH1() {
		return h1;
	}
	
	public Element getH2() {
		return h2;
	}
	
	
	public Element getW1() {
		return w1;
	}

	public BigInteger getN1() {
		return N1;
	}
	
	public BigInteger getN2() {
		return N2;
	}
	
	public RSAPublicKey getRSAPublicKey1() {
		return pk1;
	}
	
	public RSAPublicKey getRSAPublicKey2() {
		return pk2;
	}

	public int getMaxBinaryTimeLength() {
		return maxBinaryTimeLength;
	}
	private void readObject(ObjectInputStream objectInputStream) throws ClassNotFoundException, IOException {
		objectInputStream.defaultReadObject();
		Pairing pairing = PairingFactory.getPairing(this.pairingParameters);
		this.g = pairing.getG1().newElementFromBytes(this.byteArrayG).getImmutable();
		this.g1 = pairing.getG1().newElementFromBytes(this.byteArrayG1).getImmutable();
		this.g2 = pairing.getG1().newElementFromBytes(this.byteArrayG2).getImmutable();
		this.g3 = pairing.getG1().newElementFromBytes(this.byteArrayG3).getImmutable();
		this.g4 = pairing.getG1().newElementFromBytes(this.byteArrayG4).getImmutable();
		this.eghAlpha = pairing.getGT().newElementFromBytes(this.byteArrayEghAlpha).getImmutable();
		this.gBeta = pairing.getG1().newElementFromBytes(this.byteArrayGBeta).getImmutable();
		this.h = pairing.getG1().newElementFromBytes(this.byteArrayH).getImmutable();
		this.h1 = pairing.getG1().newElementFromBytes(this.byteArrayH1).getImmutable();
		this.h2 = pairing.getG1().newElementFromBytes(this.byteArrayH2).getImmutable();
		this.w1 = pairing.getG1().newElementFromBytes(this.byteArrayW1).getImmutable();
		
	}
	
}
