/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.flink.cdc.runtime.functions.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

/** Encryption / decryption built-in functions. */
public class EncryptionFunctions {

    private static final Logger LOG = LoggerFactory.getLogger(EncryptionFunctions.class);

    // ------------------------------------------------------------------
    // Hash functions
    // ------------------------------------------------------------------

    /** Returns the MD5 hex digest of the given string, or null if input is null. */
    public static String md5(String str) {
        if (str == null) {
            return null;
        }
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(str.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(digest);
        } catch (Exception e) {
            LOG.error("md5() failed", e);
            return null;
        }
    }

    /** Returns the SHA-256 hex digest of the given string, or null if input is null. */
    public static String sha256(String str) {
        if (str == null) {
            return null;
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(str.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(digest);
        } catch (Exception e) {
            LOG.error("sha256() failed", e);
            return null;
        }
    }

    /** Returns the SHA-512 hex digest of the given string, or null if input is null. */
    public static String sha512(String str) {
        if (str == null) {
            return null;
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            byte[] digest = md.digest(str.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(digest);
        } catch (Exception e) {
            LOG.error("sha512() failed", e);
            return null;
        }
    }

    // ------------------------------------------------------------------
    // AES functions  (AES/CBC/PKCS5Padding, key padded/truncated to 16 bytes)
    // ------------------------------------------------------------------

    /**
     * Encrypts {@code plainText} with AES/CBC/PKCS5Padding using {@code secretKey}. The key is
     * zero-padded or truncated to 16 bytes (AES-128). Returns a Base64-encoded string that
     * contains the 16-byte IV prepended to the cipher text, or null on any error.
     */
    public static String aesEncrypt(String plainText, String secretKey) {
        if (plainText == null || secretKey == null) {
            return null;
        }
        try {
            byte[] keyBytes = normalizeKey(secretKey, 16);
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // Use the key bytes (first 16) as IV for deterministic output
            IvParameterSpec iv = new IvParameterSpec(keyBytes);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
            byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            LOG.error("aesEncrypt() failed", e);
            return null;
        }
    }

    /**
     * Decrypts a Base64-encoded AES/CBC/PKCS5Padding cipher text produced by {@link
     * #aesEncrypt(String, String)}, or null on any error.
     */
    public static String aesDecrypt(String encryptedText, String secretKey) {
        if (encryptedText == null || secretKey == null) {
            return null;
        }
        try {
            byte[] keyBytes = normalizeKey(secretKey, 16);
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec iv = new IvParameterSpec(keyBytes);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            LOG.error("aesDecrypt() failed", e);
            return null;
        }
    }

    // ------------------------------------------------------------------
    // Encoding helpers
    // ------------------------------------------------------------------

    /** Returns the Base64 encoding of the given string, or null if input is null. */
    public static String toBase64(String str) {
        if (str == null) {
            return null;
        }
        return Base64.getEncoder().encodeToString(str.getBytes(StandardCharsets.UTF_8));
    }

    /** Decodes a Base64-encoded string, or null if input is null or decoding fails. */
    public static String fromBase64(String str) {
        if (str == null) {
            return null;
        }
        try {
            return new String(Base64.getDecoder().decode(str), StandardCharsets.UTF_8);
        } catch (Exception e) {
            LOG.error("fromBase64() failed", e);
            return null;
        }
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    private static byte[] normalizeKey(String key, int length) {
        byte[] raw = key.getBytes(StandardCharsets.UTF_8);
        if (raw.length == length) {
            return raw;
        }
        return Arrays.copyOf(raw, length); // zero-pads if shorter, truncates if longer
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}