package com.xjeffrose.seatec.X509;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.Date;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import sun.security.util.DerOutputStream;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class X509Certificate extends java.security.cert.X509Certificate {

  Date startDate ;                // time from which certificate is valid
  Date expiryDate ;               // time after which certificate is not valid
  BigInteger serialNumber ;       // serial number for certificate
  PrivateKey caKey ;              // private key of the certifying authority (ca) certificate
  java.security.cert.X509Certificate caCert ;        // public key certificate of the certifying authority
  KeyPair keyPair ;               // public/private key pair that we are creating certificate for
  X509CertificateGenerator certGen = new X509CertificateGenerator();
  X500Principal subjectName = new X500Principal("CN=Test V3 Certificate");
  ObjectIdentifier signatureAlgorithm = AlgorithmId.sha256WithRSAEncryption_oid;

  private final X509CertInfo info;
  private boolean readOnly = false;
  private AlgorithmId algId;
  private byte[] signature;
  private byte[] signedCert;

  public X509Certificate(X509CertInfo info) {
    this.info = info;
  }

  public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {

  }

  public void checkValidity(Date date)
      throws CertificateExpiredException, CertificateNotYetValidException {

  }

  public int getVersion() {
    return 0;
  }

  public BigInteger getSerialNumber() {
    return null;
  }

  public Principal getIssuerDN() {
    return null;
  }

  public Principal getSubjectDN() {
    return null;
  }

  public Date getNotBefore() {
    return null;
  }

  public Date getNotAfter() {
    return null;
  }

  public byte[] getTBSCertificate() throws CertificateEncodingException {
    return new byte[0];
  }

  public byte[] getSignature() {
    return signature;
  }

  public String getSigAlgName() {
    return null;
  }

  public String getSigAlgOID() {
    return null;
  }

  public byte[] getSigAlgParams() {
    return new byte[0];
  }

  public boolean[] getIssuerUniqueID() {
    return new boolean[0];
  }

  public boolean[] getSubjectUniqueID() {
    return new boolean[0];
  }

  public boolean[] getKeyUsage() {
    return new boolean[0];
  }

  public int getBasicConstraints() {
    return 0;
  }

  public byte[] getEncoded() throws CertificateEncodingException {
    return new byte[0];
  }

  public void verify(PublicKey key)
      throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {

  }

  public void verify(PublicKey key, String sigProvider)
      throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {

  }

  public String toString() {
    return null;
  }

  public PublicKey getPublicKey() {
    return null;
  }

  public boolean hasUnsupportedCriticalExtension() {
    return false;
  }

  public Set<String> getCriticalExtensionOIDs() {
    return null;
  }

  public Set<String> getNonCriticalExtensionOIDs() {
    return null;
  }

  public byte[] getExtensionValue(String oid) {
    return new byte[0];
  }


  public void sign(PrivateKey key, String algorithm) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
    this.sign(key, algorithm, (String)null);
  }

  public void sign(PrivateKey key, String algorithm, String provider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
    try {
      if(readOnly) {
        throw new CertificateEncodingException("cannot over-write existing certificate");
      } else {
        Signature sigEngine = null;
        if(provider != null && provider.length() != 0) {
          sigEngine = Signature.getInstance(algorithm, provider);
        } else {
          sigEngine = Signature.getInstance(algorithm);
        }

        sigEngine.initSign(key);
        this.algId = AlgorithmId.get(sigEngine.getAlgorithm());
        DerOutputStream out = new DerOutputStream();
        DerOutputStream tmp = new DerOutputStream();
        this.info.encode(tmp);
        byte[] rawCert = tmp.toByteArray();
        this.algId.encode(tmp);
        sigEngine.update(rawCert, 0, rawCert.length);
        this.signature = sigEngine.sign();
        tmp.putBitString(this.signature);
        out.write((byte) 48, tmp);
        this.signedCert = out.toByteArray();
        this.readOnly = true;
      }
    } catch (IOException e) {
      throw new CertificateEncodingException(e.toString());
    }
  }

  /// REMOVE THIS ----------------
  public Object get(String sigAlg) {
    return null;
  }
}
