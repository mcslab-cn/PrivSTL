package com.buptmcs.privstg.generator;


import com.buptmcs.privstg.parameters.CiphertextCandDecryptA;
import com.buptmcs.privstg.parameters.RetrieveKey;

import it.unisa.dia.gas.jpbc.Element;

public class DecryptionGenerator {
    public static Element decrypt(CiphertextCandDecryptA ca, RetrieveKey userRandomNumber) throws Exception {
        Element C = ca.getC().getImmutable();
        Element A = ca.getA().getImmutable();
        Element tau = userRandomNumber.getTau().getImmutable();
        Element DK = C.div(A.powZn(tau.invert())).getImmutable();
        return DK;
    }
}
