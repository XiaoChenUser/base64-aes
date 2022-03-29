package com.example;

import org.apache.commons.codec.binary.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Base64;

/**
 * Base64 + AES/ECB/PKCS7Padding 加解密字符串
 * 由于 Java 对 PKCS7Padding 支持的不是很好，自己实现。
 */
public class AesAlgorithm {

    static {
        Security.removeProvider("BC");
        Security.addProvider(new BouncyCastleProvider());
    }


    public static void main(String[] args) {
        String str = "Hello world";
        String aesKey = "#G$&^jgfujy6ujxt";

        if(!aesKeyCheck(aesKey)){
            System.out.println("key bytes:" + aesKey.getBytes().length);
            throw new RuntimeException("AES key length not 128/192/256 bits.");
        }

        try {
            //1.加密：(明文)str1 (aes encrypt) -> bytes (base64 encrypt) -> (密文)str2
            byte[] encrypt = aesEncrypt(str, aesKey);
            String base64Str = base64Encrypt(encrypt);
            System.out.println("Base64 string:" + base64Str);

            //2.解密：(密文)str2 (base64 decrypt) -> bytes (aes decrypt) -> (明文)str1
            byte[] base64DecryptBytes = base64Decrypt(base64Str);
            String decrypt = aesDecrypt(base64DecryptBytes, aesKey);
            System.out.println("AES Decrypt:" + decrypt);

            //3.不分步骤 AES + Base64 encrypt & decrypt
            String encrypted = aesBase64Encrypt(str, aesKey);
            System.out.println("encrypted:" + encrypted);
            String result = base64AESDecrypt(encrypted, aesKey);
            System.out.println("AES + base64:" + result);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }


    private static boolean aesKeyCheck(String aesKey) {
        int length = aesKey.getBytes().length;
        if (length / 128 == 0 || length / 192 == 0 || length / 256 == 0) {
            return true;
        }
        return false;
    }

    public static String base64Encrypt(byte[] bytes) {
        return new String(org.apache.commons.codec.binary.Base64.encodeBase64(bytes), StandardCharsets.UTF_8);
    }

    public static byte[] base64Decrypt(String str) {
        return org.apache.commons.codec.binary.Base64.decodeBase64(StringUtils.getBytesUtf8(str));
    }



    public static byte[] aesEncrypt(String str, String aesKey) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //创建一个实现指定转换的 Cipher对象，该转换由指定的提供程序提供。
        //"AES/ECB/PKCS7Padding"：转换的名称；"BC"：提供程序的名称
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");

        SecretKeySpec keySpec = new SecretKeySpec(aesKey.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(str.getBytes());
    }

    public static String aesDecrypt(byte[] bytes, String aesKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(aesKey.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding","BC");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        byte[] decrypt = cipher.doFinal(bytes);
        return new String(decrypt,StandardCharsets.UTF_8);
    }

    public static String aesBase64Encrypt(String str, String aesKey) throws NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException {
        return Base64.getEncoder().encodeToString(aesEncrypt(str, aesKey));
    }

    public static String base64AESDecrypt(String str, String aesKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        return aesDecrypt(Base64.getDecoder().decode(str.getBytes(StandardCharsets.UTF_8)), aesKey);
    }
}
