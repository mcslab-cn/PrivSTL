package com.buptmcs.privstg.generator;

import java.util.HashMap;
import java.util.Map;

import com.buptmcs.privstg.parameters.GT;
import com.buptmcs.privstg.parameters.PublicKey;
import com.buptmcs.util.GeneratorUtils;

import ch.hsr.geohash.GeoHash;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class GTGenerator {
    public static GT generateGT(PublicKey publicKey, double[] location) {
        PairingParameters pairingParameters = publicKey.getPairingParameters();
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        Element epsilon1 = pairing.getZr().newRandomElement().getImmutable();
        Element epsilon2 = pairing.getZr().newRandomElement().getImmutable();
        Element K0 = publicKey.getG().powZn(epsilon1).getImmutable();
        Element egh = pairing.pairing(publicKey.getG1(), publicKey.getH()).getImmutable();
        Element K1 = egh.powZn(epsilon1).getImmutable();
        Element K2 = egh.powZn(epsilon2).getImmutable();
        Element He2 = publicKey.getH1().powZn(epsilon2).getImmutable();
        Map<Integer, Element> Ks = new HashMap<>();
        for (int i = 4; i <= 6; i++) {
            GeoHash geoHash = GeoHash.withCharacterPrecision(location[0], location[1], i);
            byte[] hashGeoHash = GeneratorUtils.hash(geoHash.toBase32().getBytes());
            Element hGeoHash = pairing.getZr().newElementFromHash(hashGeoHash, 0, hashGeoHash.length).getImmutable();
            Ks.put(i, He2.mul(publicKey.getH().powZn(hGeoHash.mulZn(epsilon1))).getImmutable());
        }
        return new GT(pairingParameters, K0, K1, K2, Ks);
    }
}
