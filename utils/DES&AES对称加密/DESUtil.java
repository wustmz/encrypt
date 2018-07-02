package com.mz.utils;


import com.sun.org.apache.xml.internal.security.utils.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author mz
 * @Description：DES加密解密工具
 * @date 2018/7/2
 * @time 16:06
 */
public class DESUtil {
    public static final String algorithm = "DES";

    /**
     * DES加密
     * @param transformation：DES/ECB/PKCS5Padding
     * @param key：8个字节
     * @param original：内容字节长度无限制
     * @return
     * @throws Exception
     */
    public static String encryptByDES(String transformation,String key,String original) throws Exception {
        // 获取Cipher
        Cipher cipher = Cipher.getInstance(transformation);

        // 指定密钥规则
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), algorithm);

        // 指定模式(加密)和密钥
        // 创建初始向量
        IvParameterSpec iv = new IvParameterSpec(key.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        //  cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);
        // 加密
        byte[] bytes = cipher.doFinal(original.getBytes());
        // 输出加密后的数据
        // com.sun.org.apache.xml.internal.security.utils.Base64
        return Base64.encode(bytes);
    }

    /**
     * DES解密
     * @param encrypted
     * @param transformation
     * @param key
     * @return
     * @throws Exception
     */
    public static String decryptByDES(String transformation,String key,String encrypted) throws Exception {
        // 获取Cipher
        Cipher cipher = Cipher.getInstance(transformation);

        // 指定密钥规则
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), algorithm);

        // 指定模式(解密)和密钥
        // 创建初始向量
        IvParameterSpec iv = new IvParameterSpec(key.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        //  cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);
        // 解码密文
        // com.sun.org.apache.xml.internal.security.utils.Base64
        byte[] decode = Base64.decode(encrypted);
        // 解密
        byte[] bytes = cipher.doFinal(decode);
        // 输出解密后的数据
        return new String(bytes);
    }

}
