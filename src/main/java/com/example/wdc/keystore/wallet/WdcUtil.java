package com.example.wdc.keystore.wallet;

import com.example.wdc.keystore.crypto.*;
import com.example.wdc.keystore.util.Base58Utility;
import com.example.wdc.keystore.util.ByteUtil;
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
        if (password.length()>20 || password.length()<8){
            throw new Exception("请输入8-20位密码");
        }else {
            KeyPair keyPair = KeyPair.generateEd25519KeyPair();
            PublicKey publicKey = keyPair.getPublicKey();
            byte[] salt = new byte[saltLength];
            byte[] iv = new byte[ivLength];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            SecureRandom sr = new SecureRandom();
            sr.nextBytes(salt);
            ArgonManage argon2id = new ArgonManage(ArgonManage.Type.ARGON2id, salt);
            AESManage aes = new AESManage(iv);

            byte[] derivedKey = argon2id.hash(password.getBytes());
            byte[] cipherPrivKey = aes.encrypt(derivedKey, keyPair.getPrivateKey().getBytes());
            byte[] mac = SHA3Utility.keccak256(Bytes.concat(
                    derivedKey,cipherPrivKey
                    )
            );
            String b= Hex.encodeHexString(iv);

            Crypto crypto = new Crypto(
                    AESManage.cipher, Hex.encodeHexString(cipherPrivKey),
                    new Cipherparams(
                            Hex.encodeHexString(iv)
                    )
            );
            Kdfparams kdfparams = new Kdfparams(ArgonManage.memoryCost,ArgonManage.timeCost,ArgonManage.parallelism, Hex.encodeHexString(salt));

            com.example.wdc.keystore.account.Address ads = new com.example.wdc.keystore.account.Address(publicKey);
            ArgonManage params = new ArgonManage(salt);
            Keystore ks = new Keystore(ads.getAddress(), crypto, Utils.generateUUID(),
                    defaultVersion, Hex.encodeHexString(mac), argon2id.kdf(),kdfparams
            );
            return ks;
        }
    }

    /*
        地址生成逻辑
       1.对公钥进行SHA3-256哈希，再进行RIPEMD-160哈希，
           得到哈希值r1
      2.在r1前面附加一个字节的版本号:0x01
           得到结果r2
      3.将r1进行两次SHA3-256计算，得到结果r3，
           获得r3的前面4个字节，称之为b4
      4.将b4附加在r2的后面，得到结果r5
      5.将r5进行base58编码，得到结果r6
      6.r6就是地址

   */
    public static String byteToAddress(byte[] pubkey){
        byte[] pub256 = SHA3Utility.keccak256(pubkey);
        byte[] r1 = RipemdUtility.ripemd160(pub256);
        byte[] r2 = ByteUtil.prepend(r1,(byte)0x00);
        byte[] r3 = SHA3Utility.keccak256(SHA3Utility.keccak256(r1));
        byte[] b4 = ByteUtil.bytearraycopy(r3,0,4);
        byte[] b5 = ByteUtil.byteMerger(r2,b4);
        String s6 = Base58Utility.encode(b5);
        return s6 ;
    }

    /**
     *    1.将地址进行base58解码，得到结果r5
     *    2.将r5移除后后面4个字节得到r2
     *    3.将r2移除第1个字节:0x01得到r1(公钥哈希值)
     * @param address
     * @return
     */
    public static byte[] addressToPubkey(String address){
        byte[] r5 = Base58Utility.decode(address);
        byte[] r2 = ByteUtil.bytearraycopy(r5,0,21);
        byte[] r1 = ByteUtil.bytearraycopy(r2,1,20);
        return r1;
    }

}
