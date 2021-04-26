package com.buptmcs.privstg.generator;

import java.util.Set;

import com.buptmcs.privstg.geotree.GeoTree;
import com.buptmcs.privstg.geotree.Node;
import com.buptmcs.privstg.parameters.Ciphertext;
import com.buptmcs.privstg.parameters.CiphertextAndGT;
import com.buptmcs.privstg.parameters.GT;

import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class GridComGenerator {


    public static GeoTree addCiphertext2GeoTree(GeoTree geoTree, CiphertextAndGT ciphertextAndGT) {
        Ciphertext ciphertext = ciphertextAndGT.getCiphertext();
        GT gt = ciphertextAndGT.getGt();
        PairingParameters pairingParameters = gt.getPairingParameters();
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        Node root = geoTree.getRoot();
        Node node = findL6Node(root, gt, pairing);
        if (node != null) {
            node.getCiphertexts().add(ciphertext);
        }
        return geoTree;
    }

    private static Node findL6Node(Node node, GT gt, Pairing pairing) {
        // TODO Auto-generated method stub
        Set<Node> children = node.getChildren();
        for (Node child : children) {
            int level = child.getLevel();
            boolean b = pairing.pairing(gt.getKs().get(level), child.getL0()).mul(gt.getK1().powZn(child.getL1())).equals(pairing.pairing(child.getL3(), gt.getK0()).mul(gt.getK2().powZn(child.getL2())));
            if (b) {
                if (level == 6) {
                    return child;
                } else {
                    return findL6Node(child, gt, pairing);
                }
            }
        }
        return null;
    }

    public static Node judgeSearchNode(GeoTree geoTree, GT gt) {
        PairingParameters pairingParameters = gt.getPairingParameters();
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        Node root = geoTree.getRoot();
        Node node = findL6Node(root, gt, pairing);
        return node;
    }

}
