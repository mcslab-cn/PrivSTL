package com.buptmcs.util;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class PolicyUtil {

    public static void main(String[] args) {
        String accessPolicyString = "distance<1000 and date>121 and student";
        String comparableAttributeMaxValue = "distance:1023 date:366";
        Map<String, Integer> binaryLength = getComparableAttributeBinaryLength(comparableAttributeMaxValue);
        accessPolicyString = policyReplace(accessPolicyString, binaryLength);
        System.out.println(accessPolicyString);
        String[] userAttributes = new String[]{"distance=750", "date=189", "student"};
        userAttributes = attributeReplace(userAttributes, binaryLength);
        System.out.println(Arrays.toString(userAttributes));
    }

    public static Map<String, Integer> getComparableAttributeBinaryLength(String value) {
        Map<String, Integer> cabl = new HashMap<String, Integer>();
        value = value.trim();
        value = value.replaceAll("\\(", "( ");
        value = value.replaceAll("\\)", " )");
        String[] valueSplit = value.split(" ");
        for (String segment : valueSplit) {
            if (segment.contains(":")) {
                String[] segmentSplit = segment.split(":");
                int decimal = Integer.parseInt(segmentSplit[1]);
                String binary = Integer.toBinaryString(decimal);
                cabl.put(segmentSplit[0], binary.length());
            }
        }
        return cabl;
    }

    public static String policyReplace(String policy, Map<String, Integer> binaryLength) {
        policy = policy.trim();
        policy = policy.replaceAll("\\(", "( ");
        policy = policy.replaceAll("\\)", " )");
        String[] policySplit = policy.split(" ");
        for (int i = 0; i < policySplit.length; i++) {
            String segment = policySplit[i];
            if (segment.contains("<")) {
                String[] segmentSplit = segment.split("<");
                int decimal = Integer.parseInt(segmentSplit[1]);
                String binary = decimal2Binary(decimal, binaryLength.get(segmentSplit[0]));
                Set<String> b1_encoding = get1_encoding(binary);
                Set<String> extendAttributeSet = getExtendAttribute(segmentSplit[0], "<x", b1_encoding);
                String subtree = generateSubtree(extendAttributeSet);
                policySplit[i] = subtree;
            }
            if (segment.contains(">")) {
                String[] segmentSplit = segment.split(">");
                int decimal = Integer.parseInt(segmentSplit[1]);
                String binary = decimal2Binary(decimal, binaryLength.get(segmentSplit[0]));
                Set<String> b0_encoding = get0_encoding(binary);
                Set<String> extendAttributeSet = getExtendAttribute(segmentSplit[0], ">x", b0_encoding);
                String subtree = generateSubtree(extendAttributeSet);
                policySplit[i] = subtree;
            }
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < policySplit.length; i++) {
            sb.append(policySplit[i]).append(" ");
        }
        return sb.toString();
    }

    public static String[] attributeReplace(String[] attributes, Map<String, Integer> binaryLength) {
        Set<String> attributeSet = new HashSet<>();
        for (String attribute : attributes) {
            attribute = attribute.trim();
            if (attribute.contains("=")) {
                String[] attributeSplit = attribute.split("=");
                int decimal = Integer.parseInt(attributeSplit[1]);
                String binary = decimal2Binary(decimal, binaryLength.get(attributeSplit[0]));
                Set<String> b0_encoding = get0_encoding(binary);
                Set<String> extend0AttributeSet = getExtendAttribute(attributeSplit[0], "<x", b0_encoding);
                attributeSet.addAll(extend0AttributeSet);
                Set<String> b1_encoding = get1_encoding(binary);
                Set<String> extend1AttributeSet = getExtendAttribute(attributeSplit[0], ">x", b1_encoding);
                attributeSet.addAll(extend1AttributeSet);
            } else {
                attributeSet.add(attribute);
            }
        }

        return attributeSet.toArray(new String[attributeSet.size()]);
    }

    public static String decimal2Binary(int decimal, int length) {
        String binary = Integer.toBinaryString(decimal);
        while (binary.length() < length) {
            StringBuilder sb = new StringBuilder();
            sb.append("0").append(binary);
            binary = sb.toString();
        }
        return binary;
    }

    public static Set<String> get0_encoding(String binary) {
        Set<String> b0_encoding = new HashSet<>();
        char[] charArrayB = binary.toCharArray();
        for (int i = 0; i < charArrayB.length; i++) {
            if (charArrayB[i] == '0') {
                StringBuilder sb = new StringBuilder();
                sb.append(charArrayB, 0, i).append('1');
                b0_encoding.add(sb.toString());
            }
        }

        return b0_encoding;
    }

    public static Set<String> get1_encoding(String binary) {
        Set<String> b1_encoding = new HashSet<>();
        char[] charArrayB = binary.toCharArray();
        for (int i = 0; i < charArrayB.length; i++) {
            if (charArrayB[i] == '1') {
                StringBuilder sb = new StringBuilder();
                sb.append(charArrayB, 0, i + 1);
                b1_encoding.add(sb.toString());
            }
        }
        return b1_encoding;
    }

    public static Set<String> getExtendAttribute(String attribute, String symbol, Set<String> encodingSet) {
        Set<String> extendAttributeSet = new HashSet<>();
        for (String encoding : encodingSet) {
            StringBuilder sb = new StringBuilder();
            sb.append(attribute).append("||").append(symbol).append("||").append(encoding);
            extendAttributeSet.add(sb.toString());
        }
        return extendAttributeSet;
    }

    public static String generateSubtree(Set<String> extendAttributeSet) {
        StringBuilder sb = new StringBuilder();
        sb.append("( ");
        int j = 0;
        for (String extendAttribute : extendAttributeSet) {

            if (++j < extendAttributeSet.size()) {
                sb.append(extendAttribute).append(" or ");
            } else {
                sb.append(extendAttribute);
            }
        }
        sb.append(" )");
        return sb.toString();
    }

}
