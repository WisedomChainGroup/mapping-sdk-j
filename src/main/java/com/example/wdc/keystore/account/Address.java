package com.example.wdc.keystore.account;


import com.example.wdc.keystore.crypto.SHA3Utility;
import org.apache.commons.codec.binary.Hex;


import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

import static com.example.wdc.keystore.util.Utils.isInteger;

public class Address {

    //hex string,not include 0x prefix
    private  String address;


    /*
    1. 地址生成逻辑

    2. 对公钥进行SHA3-256计算，获得结果为s1

    3. 取得s1的后面22字节，并且在前面附加3个字符（WXC，大写字符），共25字节，结果为s2
    */
    private  String pubkeyToAddress(PublicKey publicKey){
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
    public Address(PublicKey publicKey){
        this.address = pubkeyToAddress(publicKey);
    }

    public String getAddress() {
        return address;
    }

}
