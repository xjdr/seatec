package com.xjeffrose.seatec.X509;

import java.util.Date;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;


//csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
//...     # Provide various details about who we are.
//    ...     x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
//    ...     x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
//    ...     x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
//    ...     x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
//    ...     x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
//    ... ])).add_extension(
//    ...     x509.SubjectAlternativeName([
//    ...         # Describe what sites we want this certificate for.
//    ...         x509.DNSName(u"mysite.com"),
//    ...         x509.DNSName(u"www.mysite.com"),
//    ...         x509.DNSName(u"subdomain.mysite.com"),
//    ...     ]),
//    ...     critical=False,

//
//Certificate Request:
//    Data:
//    Version: 0 (0x0)
//    Subject: C=US, ST=Michigan, L=Grand Rapids, O=Internet Widgits Pty Ltd, CN=www.example.com
//    Subject Public Key Info:
//    Public Key Algorithm: rsaEncryption
//    RSA Public Key: (2014 bit)
//    Modulus (2014 bit):
//    2f:40:9b:bb:fa:3f:2e:0a:71:7c:f7:7a:57:2c:09:
//    [...]
//    Exponent: 65537 (0x10001)
//    Attributes:
//    Requested Extensions:
//    X509v3 Basic Constraints:
//    CA:FALSE
//    X509v3 Key Usage:
//    Digital Signature, Non Repudiation, Key Encipherment
//    X509v3 Subject Alternative Name:
//    DNS:www.example.net, DNS:www.example.org
//    Signature Algorithm: sha1WithRSAEncryption
//    06:40:f5:c8:38:d9:f8:52:8d:62:3c:12:0c:b3:12:e4:64:88:

@Data
@Builder
@AllArgsConstructor
public class X509CertificateSigningRequest {

  private String C;
  private String ST;
  private String L;
  private String O;
  private String CN;
  private List<String> DNS;

  private String publicKey;

//  private String countryName;
//  private String state;
//  private String locality;
//  private String organizationName;
//  private String commonName;
//  private List<String> DNS;

}
