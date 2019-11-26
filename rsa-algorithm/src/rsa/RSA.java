package rsa;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;
import java.util.Scanner;

public class RSA {

	private final static SecureRandom random = new SecureRandom();
	public static final int BITSIZE = 100;
	public static final BigInteger ZERO = BigInteger.ZERO;
	public static final BigInteger ONE = BigInteger.ONE;
	public static final BigInteger MINUSONE = BigInteger.valueOf(-1);
	public static final BigInteger TWO = BigInteger.valueOf(2);
	public static final int[] ALAP = { 2, 5, 7, 9 };

	public static boolean testPr(BigInteger n, BigInteger a, int s, BigInteger d) {
		for (int i = 0; i < s; i++) {
			BigInteger exp = TWO.pow(i);
			exp = exp.multiply(d);
			BigInteger res = a.modPow(exp, n);
			if (res.equals(n.subtract(ONE)) || res.equals(ONE)) {
				return true;
			}
		}
		return false;
	}

	public static boolean millerRabin(BigInteger n, int numValues) {
		BigInteger d = n.subtract(ONE);
		int s = 0;
		while (d.mod(TWO).equals(ZERO)) {
			s++;
			d = d.divide(TWO);
		}
		for (int i = 0; i < numValues; i++) {
			BigInteger a = BigInteger.valueOf(ALAP[i]);
			boolean r = testPr(n, a, s, d);
			if (!r) {
				return false;
			}
		}
		return true;
	}

	public static BigInteger nextRandomBigInteger(BigInteger phi) {
		Random rand = new Random();
		BigInteger result = new BigInteger(phi.bitLength(), rand);
		while (result.compareTo(phi) > 0 && result.compareTo(ONE) < 0) {
			result = new BigInteger(phi.bitLength(), rand);
		}
		return result;
	}

	private static BigInteger toBigInt(byte[] arr) {
		byte[] rev = new byte[arr.length + 1];
		for (int i = 0, j = arr.length; j > 0; i++, j--)
			rev[j] = arr[i];
		return new BigInteger(rev);
	}

	public static BigInteger encrypt(BigInteger message, BigInteger e, BigInteger modulus) {
		return message.modPow(e, modulus);
	}

	public static BigInteger decrypt(BigInteger encrypted, BigInteger d, BigInteger modulus) {
		return encrypted.modPow(d, modulus);
	}

	public static BigInteger crtDecrypt(BigInteger msgToDecrypt, BigInteger e, BigInteger d, BigInteger p, BigInteger q,
			BigInteger c) {
		BigInteger m = null, dp = null, dq = null, qInv = null, m1, m2, h;
		dp = e.modInverse(p.subtract(ONE));
		dq = e.modInverse(q.subtract(ONE));
		qInv = (q.modInverse(p));
		m1 = c.modPow(dp, p);
		m2 = c.modPow(dq, q);
		h = qInv.multiply((m1.subtract(m2))).mod(p);

		m = m2.add(h.multiply(q));

		return m;
	}

	public static BigInteger gyorshatvany(BigInteger alap, BigInteger exp, BigInteger mod) {
		alap = alap.mod(mod);
		if (exp.equals(ZERO)) {
			return ZERO;
		} else if (exp.equals(ONE)) {
			return alap;
		} else if (exp.mod(TWO).equals(ZERO)) {
			return gyorshatvany(alap.multiply(alap).mod(mod), exp.divide(TWO), mod);
		} else {
			return alap.multiply(gyorshatvany(alap, exp.subtract(ONE), mod)).mod(mod);
		}
	}

	public static void main(String[] args) {

		// privateKey = d
		// publicKey = e

		BigInteger n = null, phi = null, e = null, d = null, bigIntegerMessage = null, encrypted = null,
				decrypted = null, crtDecrypt = null, c = null;
		byte[] byteMessage;
		byte[] decryptedByte;
		byte[] crtDecryptByte;
		String decryptedStringMessage;
		String crtDecryptByteStringMessage;
		Random rand = new SecureRandom();

//		BigInteger p = new BigInteger("11");
//		BigInteger q = new BigInteger("13");

		BigInteger p = BigInteger.probablePrime(BITSIZE, new SecureRandom());
		BigInteger q = BigInteger.probablePrime(BITSIZE, new SecureRandom());

		if (millerRabin(p, ALAP.length) && millerRabin(q, ALAP.length)) {
			n = p.multiply(q);
			phi = (p.subtract(ONE)).multiply(q.subtract(ONE));
		}

		// beállítjuk az e értékét
		do {
			e = new BigInteger(phi.bitLength(), rand);
		} while (e.compareTo(BigInteger.ONE) <= 0 || e.compareTo(phi) >= 0 || !e.gcd(phi).equals(BigInteger.ONE));

		d = e.modInverse(phi);

		System.out.println("D:" + d.toString());
		System.out.println("E:" + e.toString());

		Scanner sc = new Scanner(System.in);
		String message = sc.next();

		// Stringet byte tömbé alakítom
		byteMessage = message.getBytes();

		System.out.println("byteMessage:" + byteMessage);

		// konvert to BigInteger

		bigIntegerMessage = new BigInteger(message.getBytes());

		System.out.println("BigInteger Message:" + bigIntegerMessage);

		// kódolás
		encrypted = encrypt(bigIntegerMessage, e, n);

		System.out.println("encrypted:" + encrypted.toString());

		// visszafejtes
		decrypted = decrypt(encrypted, d, n);
		c = bigIntegerMessage.modPow(e, n);
		System.out.println("c:" + c.toString());
		crtDecrypt = crtDecrypt(encrypted, e, d, p, q, c);
//		 crtDecrypt = crtDecrypt(new BigInteger("513"), new BigInteger("3"),new BigInteger("11787"), new BigInteger("137"), new BigInteger("131"), c);

		System.out.println("dectypted: " + decrypted);
		System.out.println("kínai:" + crtDecrypt.toString());

		// újra byte tömb használata

		decryptedByte = decrypted.toByteArray();
		if (decryptedByte[0] == 0) {
			byte[] tmp = new byte[decryptedByte.length - 1];
			System.arraycopy(decryptedByte, 1, tmp, 0, tmp.length);
			decryptedByte = tmp;
		}
		System.out.println("decryptedByte: " + decryptedByte);

		crtDecryptByte = crtDecrypt.toByteArray();
		if (crtDecryptByte[0] == 0) {
			byte[] tmp = new byte[crtDecryptByte.length - 1];
			System.arraycopy(crtDecryptByte, 1, tmp, 0, tmp.length);
			crtDecryptByte = tmp;
		}
		System.out.println("KínaiByte: " + crtDecryptByte);

		// String-é alakítás
		decryptedStringMessage = new String(decryptedByte);
		crtDecryptByteStringMessage = new String(crtDecryptByte);

		System.out.println("DecryptedString:" + decryptedStringMessage);
		System.out.println("Kínai:" + crtDecryptByteStringMessage);

	}
}