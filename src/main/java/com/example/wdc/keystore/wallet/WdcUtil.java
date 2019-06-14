package com.example.wdc.keystore.wallet;

import com.example.wdc.keystore.crypto.*;
import com.example.wdc.keystore.util.Utils;
import com.google.common.primitives.Bytes;
import com.google.gson.Gson;
import org.apache.commons.codec.binary.Hex;

import java.security.SecureRandom;


public class WdcUtil {
    public String address;
    public Crypto crypto;
    private static final int saltLength = 32;
    private static final int ivLength = 16;
    private static final String defaultVersion = "1";


    public static Keystore unmarshal(String in) throws com.google.gson.JsonSyntaxException {
        Gson gson = new Gson();
        return gson.fromJson(in, Keystore.class);
    }
    public static String marshal(Keystore keystore){
        Gson gson = new Gson();
        return gson.toJson(keystore);
    }
    public static Keystore fromPassword(String password) throws Exception{
		
        String address="";
        String res;
        try {
            res = Hex.encodeHexString(SHA3Utility.keccak256(publicKey.getEncoded()));
            res = res.toLowerCase().substring(res.length() - 44);

            String[] resString = res.split("");
            byte[] check = new byte[res.length()];
            for (int j=0;j<res.length();j++){
                if(isInteger(resString[j])){
                    check[j] = Byte.parseByte(resString[j]);
                }else{
                    check[j] = 0;
                }
            }
            String bstr=Hex.encodeHexString(SHA3Utility.keccak256(check));
            char[] b = bstr.toCharArray();
            char[] a = res.toCharArray();
            for(int i=0;i<a.length;i++)
                if (Character.isDigit(a[i])) {
                    address = address + a[i];
                } else {
                    if (Integer.parseInt(String.valueOf(a[i]), 16) - Integer.parseInt(String.valueOf(b[i]), 16) > 8) {
                        address=address+String.valueOf(a[i]).toUpperCase();
                    }else{
                        address = address + a[i];
                    }
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        return "WX" + address;
   
    }
}
