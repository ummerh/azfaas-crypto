package com.jet.demo.data.security.pgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Security;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPublicKey;

public class DemoRunner {
	public static void main(String[] args) {

		try {
			Security.addProvider(new BouncyCastleProvider());

			PGPPublicKey pgpKey = PGPHelperUtil.readPublicKey("public.bpg");

			KeyBasedFileProcessor.encryptBytes(new FileOutputStream("sample-data.bpg"), "sample-data.bpg",
					"This is dummy data".getBytes(), pgpKey, true, true);

			KeyBasedFileProcessor.decryptBytes(new FileInputStream("sample-data.bpg"),
					new FileInputStream("secret.bpg"), "changeit".toCharArray(),
					new FileOutputStream("sample-data.out"));

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static void testBpg() {
		try {
			Security.addProvider(new BouncyCastleProvider());

			PGPPublicKey pgpKey = PGPHelperUtil
					.readPublicKey(new ByteArrayInputStream(FileUtils.readFileToByteArray(new File("public.bpg"))));
			byte[] secretKeyBytes = FileUtils.readFileToByteArray(new File("secret.bpg"));
			char[] password = "changeit".toCharArray();
			byte[] inputBytes = "what is this".getBytes();

			ByteArrayOutputStream outOs = new ByteArrayOutputStream();
			KeyBasedFileProcessor.encryptBytes(outOs, "sample-data.bpg", inputBytes, pgpKey, true, true);

			ByteArrayInputStream encodedIs = new ByteArrayInputStream(outOs.toByteArray());

			ByteArrayOutputStream decryptOs = new ByteArrayOutputStream();
			KeyBasedFileProcessor.decryptBytes(encodedIs, new ByteArrayInputStream(secretKeyBytes), password,
					decryptOs);

			System.out.println(new String(decryptOs.toByteArray()));

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
