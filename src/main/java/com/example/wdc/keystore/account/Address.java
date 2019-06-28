package com.example.wdc.keystore.account;


import com.example.wdc.keystore.wallet.WdcUtil;

import java.security.PublicKey;

public class Address {

    //hex string,not include 0x prefix
    private  String address;
    private  String pubkeyToAddress(PublicKey publicKey){
        return WdcUtil.phta(publicKey.getEncoded());
    }
    public Address(PublicKey publicKey){
        this.address = pubkeyToAddress(publicKey);
    }

    public String getAddress() {
        return address;
    }

}
