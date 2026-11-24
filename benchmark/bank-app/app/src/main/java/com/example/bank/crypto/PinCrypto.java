package com.example.bank.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class PinCrypto {

    private static final byte[] PIN_KEY = "k3y-f0r-pin-0001".getBytes(StandardCharsets.UTF_8);

    public byte[] encryptPin(String pin) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(PIN_KEY, "AES"));
        return cipher.doFinal(pin.getBytes(StandardCharsets.UTF_8));
    }

    public byte[] encryptMemo(String memo, SecretKey key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(memo.getBytes(StandardCharsets.UTF_8));
    }

    public String newOtp() {
        Random random = new Random();
        return String.format("%06d", random.nextInt(1_000_000));
    }

    public List<String> shuffledTips(List<String> tips) {
        List<String> copy = new ArrayList<>(tips);
        Collections.shuffle(copy, new Random());
        return copy;
    }
}
