package com.buptmcs.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;

public class GeneratorUtils {
    public static final int dp = 80;

    public static byte[] hash(byte[] message) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            //Impossible to get this exception
            e.printStackTrace();
        }
        assert (md != null);
        md.update(message);
        return md.digest();
    }

    public static int[] timeToInt(String[] time) {
        // TODO Auto-generated method stub
        int[] timeInt = new int[time.length];
        for (int i = 0; i < timeInt.length; i++) {
            String[] times = time[i].split("-");
            Calendar timeCal = Calendar.getInstance();
            timeCal.set(Integer.parseInt(times[0]), Integer.parseInt(times[1]) - 1, Integer.parseInt(times[2]));
            timeInt[i] = (int) ((timeCal.getTimeInMillis() / (24 * 60 * 60 * 1000)) - 17896);//����2018-12-31������
        }
        return timeInt;
    }

    public static double toRadians(double angle) {
        // TODO Auto-generated method stub
        return angle * Math.PI / 180.0;
    }

    public static double[] latLngToCoord(double[] latLng, double cityLatitude) {
        double R = 6371000.0;
        double[] coord = new double[2];
        coord[0] = R * toRadians(latLng[0]);
        coord[1] = R * Math.cos(toRadians(cityLatitude)) * toRadians(latLng[1]);
        return coord;
    }
}
