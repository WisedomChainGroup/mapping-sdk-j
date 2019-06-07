package com.example.wdc.keystore.account;


import com.example.wdc.keystore.crypto.SHA3Utility;
import org.apache.commons.codec.binary.Hex;


import java.security.PublicKey;

public class Address {

    //hex string,not include 0x prefix
    private  String address;


    /*
    1. 地址生成逻辑

    2. 对公钥进行SHA3-256计算，获得结果为s1

    3. 取得s1的后面22字节，并且在前面附加3个字符（WXC，大写字符），共25字节，结果为s2
    */
    private  String pubkeyToAddress(PublicKey publicKey){
        String res = Hex.encodeHexString(SHA3Utility.sha3256(publicKey.getEncoded()));
        res = res.substring(res.length() - 44);
        return "WX" + res;
    }

    public Address(){

    }

    public Address(PublicKey publicKey){
        this.address = pubkeyToAddress(publicKey);
    }

    public String getAddress() {
        return address;
    }
}
