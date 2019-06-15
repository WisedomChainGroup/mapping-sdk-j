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

}
