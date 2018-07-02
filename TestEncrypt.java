package com.mz;

import com.mz.utils.AESUtil;
import com.mz.utils.DESUtil;
import com.mz.utils.DigestUtil;
import com.mz.utils.RsaUtil;
import com.mz.utils.SignatureUtil;

import org.junit.Test;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @author mz
 * @Description：
 * @date 2018/7/2
 * @time 19:48
 */
public class TestEncrypt {
    //加密内容
    private static final String s = "1234567812345678";

    /**
     * 测试DES加密解密
     *
     * @throws Exception
     */
    @Test
    public void DES() throws Exception {
        String key = "12345678";
        String des = DESUtil.encryptByDES("DES/ECB/PKCS5Padding", key, s);
        System.out.println("加密：" + des);

        String decrypt = DESUtil.decryptByDES("DES/ECB/PKCS5Padding", key, des);
        System.out.println("解密:" + decrypt);
    }

    /**
     * 测试AES加密解密
     *
     * @throws Exception
     */
    @Test
    public void AES() throws Exception {
        String key = "1234567812345678";
        String encrypt = AESUtil.encryptByAES("AES/CBC/NOPadding", key, s);
        System.out.println("加密:" + encrypt);
        String decrypt = AESUtil.decryptByAES("AES/CBC/NOPadding", key, encrypt);
        System.out.println("解密:" + decrypt);
    }

    /**
     * 测试消息摘要
     *
     * @throws Exception
     */
    @Test
    public void Digest() throws Exception {
        String digest = DigestUtil.getDigest("SHA-1", s);
        System.out.println("字符串消息摘要：" + digest);
        String digestFile = DigestUtil.getDigestFile("SHA-1", "D:/1.txt");
        System.out.println("文件消息摘要：" + digestFile);
    }

    /**
     * 测试RSA非对称性加密
     *
     * @throws Exception
     */
    @Test
    public void Rsa() throws Exception {
        //加密算法
        String algorithm = "RSA";
        //生成公私钥对
        RsaUtil.generateKeyToFile(algorithm, "a.pub", "a.pri");
        //获取公钥
        PublicKey publicKey = RsaUtil.loadPublicKeyFromFile(algorithm, "a.pub");
        //获取私钥
        PrivateKey privateKey = RsaUtil.loadPrivateKeyFromFile(algorithm, "a.pri");

        //私钥加密
        String encrypt = RsaUtil.encrypt(algorithm, s, privateKey, 245);
        //公钥解密
        String decrypt = RsaUtil.decrypt(algorithm, encrypt, publicKey, 256);
        System.out.println("加密：" + encrypt);
        System.out.println("解密：" + decrypt);
    }

    /**
     * 测试数字签名
     */
    @Test
    public void Signature() throws Exception {
        //获取公钥
        PublicKey publicKey = RsaUtil.loadPublicKeyFromFile("RSA", "a.pub");
        //获取私钥
        PrivateKey privateKey = RsaUtil.loadPrivateKeyFromFile("RSA", "a.pri");
        //获取签名数据
        String signaturedData = SignatureUtil.getSignature(s, "sha256withrsa", privateKey);
        //验证签名是否正确
        boolean b = SignatureUtil.verifySignature(s, "sha256withrsa", publicKey, signaturedData);

        System.out.println("flag:" + b);
    }

}
