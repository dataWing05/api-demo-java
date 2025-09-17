package com.example;

import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.encoders.Base64;

import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;

public class Sm2Utils {

    static {
        try {
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
                System.out.println("Bouncy Castle provider registered successfully");
            } else {
                System.out.println("Bouncy Castle provider already registered");
            }
        } catch (Exception e) {
            System.err.println("Failed to register Bouncy Castle provider: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static ECPublicKeyParameters loadPublicKey(String pemFilePath) throws Exception {
        try (FileReader fileReader = new FileReader(pemFilePath)) {
            PEMParser pemParser = new PEMParser(fileReader);
            Object pemObject = pemParser.readObject();
            pemParser.close();

            if (!(pemObject instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo)) {
                throw new Exception(
                        "PEM file does not contain a valid public key. Got: "
                                + pemObject.getClass().getName());
            }

            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            BCECPublicKey publicKey =
                    (BCECPublicKey)
                            converter.getPublicKey(
                                    (org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) pemObject);
            ECParameterSpec ecSpec = publicKey.getParameters();
            return new ECPublicKeyParameters(
                    publicKey.getQ(),
                    new org.bouncycastle.crypto.params.ECDomainParameters(
                            ecSpec.getCurve(),
                            ecSpec.getG(),
                            ecSpec.getN(),
                            ecSpec.getH(),
                            ecSpec.getSeed()));
        }
    }

    public static String encryptSM2(String publicKeyPemPath, String plaintext)
            throws Exception {
        ECPublicKeyParameters publicKey = loadPublicKey(publicKeyPemPath);
        String publicKeyHex =
                org.bouncycastle.util.encoders.Hex.toHexString(publicKey.getQ().getEncoded(false));
        System.out.println("Public Key (Hex): " + publicKeyHex);
        SM2Engine sm2Engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        // Wrap public key with random for encryption
        ParametersWithRandom param = new ParametersWithRandom(publicKey, new SecureRandom());
        sm2Engine.init(true, param);
        //        sm2Engine.init(true, publicKey);
        byte[] data = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = sm2Engine.processBlock(data, 0, data.length);
        return Base64.toBase64String(encrypted);
    }
}
