package com.mz.utils;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @author mz
 * @Description：生成消息摘要工具
 * @date 2018/7/2
 * @time 17:11
 */
public class DigestUtil {

    /**
     * 获取字符串的消息摘要
     *
     * @param algorithm : 算法：MD5、SHA-1、SHA-256、SHA-512
     * @param input     : 原文
     * @return : 消息摘要
     * @throws NoSuchAlgorithmException
     */
    public static String getDigest(String algorithm, String input) throws NoSuchAlgorithmException {
        // 获取消息摘要对象
        MessageDigest md = MessageDigest.getInstance(algorithm);
        // 获取消息摘要
        byte[] digest = md.digest(input.getBytes());

        return toHex(digest);
    }

    /**
     * 获取文件的消息摘要
     *
     * @param algorithm : 算法：MD5、SHA-1、SHA-256、SHA-512
     * @param filePath  : 文件路径
     * @return : 消息摘要
     * @throws Exception
     */
    public static String getDigestFile(String algorithm, String filePath) throws Exception {
        FileInputStream fis = new FileInputStream(filePath);
        int len;
        byte[] buffer = new byte[1024];
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        while ((len = fis.read(buffer)) != -1) {
            baos.write(buffer, 0, len);
        }

        // 获取消息摘要对象
        MessageDigest md = MessageDigest.getInstance(algorithm);
        // 获取消息摘要
        byte[] digest = md.digest(baos.toByteArray());

        return toHex(digest);

    }

    /**
     * 字节转成16进制
     *
     * @param digest
     * @return
     */
    public static String toHex(byte[] digest) {
        StringBuilder sb = new StringBuilder();

        for (byte b : digest) {
            // 转为16jinzhi进制数据
            int i = b & 0xff;
            // 转为字符串
            String hex = Integer.toHexString(i);
            // 如果长度为1,前面补0
            if (hex.length() == 1) {
                hex = 0 + hex;
            }
            sb.append(hex);
        }
        return sb.toString();
    }
}
