package com.mz.utils;

import com.sun.org.apache.xml.internal.security.utils.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author mz
 * @Description：AES加密解密工具
 * @date 2018/7/2
 * @time 16:52
 */
public class AESUtil {
    public static final String algorithm = "AES";

    /**
     * AES加密
     * @param transformation: "AES/CBC/NOPadding"
     * @param key: 字节长度必须为16
     * @param original：内容字节长度必须是16的倍数
     * @return
     * @throws Exception
     */
    public static String encryptByAES(String transformation, String key, String original) throws Exception {

        // 获取Cipher
        Cipher cipher = Cipher.getInstance(transformation);
        // 生成密钥
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), algorithm);
        // 指定模式(加密)和密钥
        // 创建初始化向量
        IvParameterSpec iv = new IvParameterSpec(key.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
        //cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        // 加密
        byte[] bytes = cipher.doFinal(original.getBytes());

        return Base64.encode(bytes);
    }

    /**
     * AES解密
     * @param transformation
     * @param key
     * @param encrypted
     * @return
     * @throws Exception
     */
    public static String decryptByAES(String transformation, String key, String encrypted) throws Exception {

        // 获取Cipher
        Cipher cipher = Cipher.getInstance(transformation);
        // 生成密钥
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), algorithm);
        // 指定模式(解密)和密钥
        // 创建初始化向量
        IvParameterSpec iv = new IvParameterSpec(key.getBytes());
        // 初始化
        cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);
        // 解密
        byte[] bytes = cipher.doFinal(Base64.decode(encrypted));

        return new String(bytes);
    }
}
