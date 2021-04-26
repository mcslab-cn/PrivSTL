package com.buptmcs.privstg.geotree;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import com.buptmcs.privstg.parameters.MasterSecretKey;
import com.buptmcs.privstg.parameters.PublicKey;
import com.buptmcs.privstg.parameters.SerializableParameters;

import ch.hsr.geohash.GeoHash;

public class GeoTree extends SerializableParameters {

    private static final long serialVersionUID = 1L;
    private Node root;
    private Map<String, Node> l6NodeMap = new HashMap<>();
    private Map<String, Node> l6NodeGeohashMap = new HashMap<>();

    public GeoTree(String[] childrenGeoHash, PublicKey publicKey, MasterSecretKey masterSecretKey) {
        root = new Node(childrenGeoHash, publicKey, masterSecretKey);
        generateL6NodeMap(root);
        generateAdjacentNodeForEachL6Node();
    }

    private void generateAdjacentNodeForEachL6Node() {
        for (String id : l6NodeMap.keySet()) {
            Node node = l6NodeMap.get(id);
            String geoHashString = node.getGeoHashString();
            GeoHash geoHash = GeoHash.fromGeohashString(geoHashString);
            GeoHash[] adjacent = geoHash.getAdjacent();
            for (GeoHash ahash : adjacent) {
                if (l6NodeGeohashMap.containsKey(ahash.toBase32())) {
                    node.getAdjacentNodeId().add(l6NodeGeohashMap.get(ahash.toBase32()).getId());
                }
            }
            GeoHash[] NorthNeighborAdjacent = adjacent[0].getAdjacent();
            for (GeoHash bhash : NorthNeighborAdjacent) {
                if (l6NodeGeohashMap.containsKey(bhash.toBase32())) {
                    node.getAdjacentNodeId().add(l6NodeGeohashMap.get(bhash.toBase32()).getId());
                }
            }
            GeoHash[] SouthNeighborAdjacent = adjacent[4].getAdjacent();
            for (GeoHash chash : SouthNeighborAdjacent) {
                if (l6NodeGeohashMap.containsKey(chash.toBase32())) {
                    node.getAdjacentNodeId().add(l6NodeGeohashMap.get(chash.toBase32()).getId());
                }
            }

        }
    }

    private void generateL6NodeMap(Node node) {
        // TODO Auto-generated method stub
        if (node.getLevel() == 6) {
            l6NodeMap.put(node.getId(), node);
            l6NodeGeohashMap.put(node.getGeoHashString(), node);
        } else {
            Set<Node> children = node.getChildren();
            for (Node child : children) {
                generateL6NodeMap(child);
            }
        }
    }

    public Node getRoot() {
        return root;
    }

    public Map<String, Node> getL6NodeMap() {
        return l6NodeMap;
    }

}
