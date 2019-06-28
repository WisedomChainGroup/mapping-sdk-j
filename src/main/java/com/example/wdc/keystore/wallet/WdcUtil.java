package com.example.wdc.keystore.wallet;

import com.example.wdc.keystore.ApiResult.APIResult;
import com.example.wdc.keystore.crypto.*;
import com.example.wdc.keystore.crypto.ed25519.Ed25519PrivateKey;
import com.example.wdc.keystore.crypto.ed25519.Ed25519PublicKey;
import com.example.wdc.keystore.util.Base58Utility;
import com.example.wdc.keystore.util.ByteUtil;
import com.example.wdc.keystore.util.ByteUtils;
import com.example.wdc.keystore.util.Utils;
import com.google.common.primitives.Bytes;
import com.google.gson.Gson;
import net.sf.json.JSONObject;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.math.BigInteger;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Arrays;

import static com.example.wdc.keystore.ApiResult.APIResult.newFailResult;
import static com.example.wdc.keystore.ApiResult.APIResult.newSuccessResult;


public class WdcUtil {
    public String address;
    public Crypto crypto;
    private static final int saltLength = 32;
    private static final int ivLength = 16;
    private static final String defaultVersion = "1";
    private static final String t = "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ec";



    public static Keystore unmarshal(String in) throws com.google.gson.JsonSyntaxException {
        Gson gson = new Gson();
        return gson.fromJson(in, Keystore.class);
    }
    public static String marshal(Keystore keystore){
        Gson gson = new Gson();
        return gson.toJson(keystore);
    }
    public static String fromPassword(String password) throws Exception{
        if (password.length()>20 || password.length()<8){
            throw new Exception("invalid password");
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
            APIResult as =  newSuccessResult(ks);
            String json = String.valueOf(JSONObject.fromObject(as));
            return  json;
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
    public static String pubkeyHashToAddress(String r1Str) throws DecoderException {
        byte[] r1 = Hex.decodeHex(r1Str.toCharArray());
        byte[] r2 = ByteUtil.prepend(r1,(byte)0x00);
        byte[] r3 = SHA3Utility.keccak256(SHA3Utility.keccak256(r1));
        byte[] b4 = ByteUtil.bytearraycopy(r3,0,4);
        byte[] b5 = ByteUtil.byteMerger(r2,b4);
        String s6 = Base58Utility.encode(b5);
        APIResult ar =  newFailResult(0,s6);
        String json = String.valueOf(JSONObject.fromObject(ar));
        return  json;
    }

    /**
     *    1.将地址进行base58解码，得到结果r5
     *    2.将r5移除后后面4个字节得到r2
     *    3.将r2移除第1个字节:0x01得到r1(公钥哈希值)
     * @param address
     * @return
     */
    public static String addressToPubkeyHash(String address){
        byte[] r5 = Base58Utility.decode(address);
        byte[] r2 = ByteUtil.bytearraycopy(r5,0,21);
        byte[] r1 = ByteUtil.bytearraycopy(r2,1,20);
        String publickeyHash =  Hex.encodeHexString(r1);
        APIResult ar =  newFailResult(0,publickeyHash);
        String json = String.valueOf(JSONObject.fromObject(ar));
        return  json;
    }


    public static byte[] decrypt(Keystore keystore,String password) throws Exception{
        if (!WdcUtil.verifyPassword(keystore,password)){
            throw new Exception("invalid password");
        }
        ArgonManage argon2id = new ArgonManage(ArgonManage.Type.ARGON2id, Hex.decodeHex(keystore.kdfparams.salt.toCharArray()));
        byte[] derivedKey = argon2id.hash(password.getBytes());
        byte[] iv = Hex.decodeHex(keystore.crypto.cipherparams.iv.toCharArray());
        AESManage aes = new AESManage(iv);
        return aes.decrypt(derivedKey, Hex.decodeHex(keystore.crypto.ciphertext.toCharArray()));
    }

    public static boolean verifyPassword(Keystore keystore,String password) throws Exception{
        // 验证密码是否正确 计算 mac
        ArgonManage argon2id = new ArgonManage(ArgonManage.Type.ARGON2id, Hex.decodeHex(keystore.kdfparams.salt.toCharArray()));
        byte[] derivedKey = argon2id.hash(password.getBytes());
        byte[] cipherPrivKey = Hex.decodeHex(keystore.crypto.ciphertext.toCharArray());
        byte[] mac = SHA3Utility.keccak256(Bytes.concat(
                derivedKey,cipherPrivKey
                )
        );
        return Hex.encodeHexString(mac).equals(keystore.mac);
    }

    public static String prikeyToPubkey(String prikey) throws Exception {
        if(prikey.length() != 64 || new BigInteger(Hex.decodeHex(prikey.toCharArray())).compareTo(new BigInteger(ByteUtils.hexStringToBytes(t))) > 0){
            throw new Exception("Private key format error");
        }
        Ed25519PrivateKey eprik = new Ed25519PrivateKey(Hex.decodeHex(prikey.toCharArray()));
        Ed25519PublicKey epuk = eprik.generatePublicKey();
        String pubkey = Hex.encodeHexString(epuk.getEncoded());
        APIResult ar =  newFailResult(0,pubkey);
        String json = String.valueOf(JSONObject.fromObject(ar));
        return  json;
    }

    public static String keystoreToPubkey(Keystore ks,String password) throws Exception {
        String privateKey =  obtainPrikey(ks,password);
        String pubkey = prikeyToPubkey(privateKey);
        APIResult ar =  newFailResult(0,pubkey);
        String json = String.valueOf(JSONObject.fromObject(ar));
        return  json;
    }
    /**
     * 地址有效性校验
     * @param address
     * @return
     */
    public static String verifyAddress(String address) throws DecoderException {
        byte[] r5 = Base58Utility.decode(address);
//        ResultSupport ar = new ResultSupport();
        if(!address.startsWith("1")){
//            jr.setStatusCode(-1);
            APIResult as =  newFailResult(-1,"地址开头字母有误");
            String str = String.valueOf(JSONObject.fromObject(as));
            return str;
        }
        byte[] r3 = SHA3Utility.keccak256(SHA3Utility.keccak256(atph(address)));
        byte[] b4 = ByteUtil.bytearraycopy(r3,0,4);
        byte[] _b4 = ByteUtil.bytearraycopy(r5,r5.length-4,4);
        if(Arrays.equals(b4,_b4)){
            APIResult as =  newFailResult(0,"正确");
            String str = String.valueOf(JSONObject.fromObject(as));
            return str;
        }else {
            APIResult as =  newFailResult(-2,"地址格式错误");
            String str = String.valueOf(JSONObject.fromObject(as));
            return  str;
        }
    }
    public static String obtainPrikey(Keystore ks,String password) throws Exception {
        String privateKey =  Hex.encodeHexString(WdcUtil.decrypt(ks,password));
        APIResult ar =  newFailResult(0,privateKey);
        String json = String.valueOf(JSONObject.fromObject(ar));
        return  json;
    }

    public static String phta(byte[] pubkey){
        byte[] pub256 = SHA3Utility.keccak256(pubkey);
        byte[] r1 = RipemdUtility.ripemd160(pub256);
        byte[] r2 = ByteUtil.prepend(r1,(byte)0x00);
        byte[] r3 = SHA3Utility.keccak256(SHA3Utility.keccak256(r1));
        byte[] b4 = ByteUtil.bytearraycopy(r3,0,4);
        byte[] b5 = ByteUtil.byteMerger(r2,b4);
        String s6 = Base58Utility.encode(b5);
        return  s6;
    }

    public static byte[] atph(String address){
        byte[] r5 = Base58Utility.decode(address);
        byte[] r2 = ByteUtil.bytearraycopy(r5,0,21);
        byte[] r1 = ByteUtil.bytearraycopy(r2,1,20);
        return  r1;
    }

}