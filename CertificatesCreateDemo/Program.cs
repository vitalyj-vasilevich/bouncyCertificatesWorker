using System;
using System.Collections;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using X509Certificate = System.Security.Cryptography.X509Certificates.X509Certificate;

namespace CertificatesCreateDemo
{
    class Program
    {
        static void Main(string[] args)
        {
            string CommonName = "TestSigned1";
            string caFile = "default.ca.crt";
            string caKey = "default.ca.key";

            IDictionary attributes = new Hashtable();
            attributes[X509Name.E] = string.Empty;
            attributes[X509Name.CN] = CommonName;
            attributes[X509Name.O] = string.Empty;
            attributes[X509Name.C] = "BY";
            attributes[X509Name.ST] = string.Empty;
            attributes[X509Name.OU] = string.Empty;
            attributes[X509Name.L] = string.Empty;

            IList orderedAttributes = new ArrayList();
            orderedAttributes.Add(X509Name.E);
            orderedAttributes.Add(X509Name.CN);
            orderedAttributes.Add(X509Name.O);
            orderedAttributes.Add(X509Name.C);
            orderedAttributes.Add(X509Name.ST);
            orderedAttributes.Add(X509Name.OU);
            orderedAttributes.Add(X509Name.L);

            AsymmetricCipherKeyPair subjectKeyPair = null;
            X509Certificate2 caCertificate = new X509Certificate2(caFile);
            var csr = GenerateCsr(attributes, out subjectKeyPair);
            X509Certificate2 signedCertificate = GetSignedCertificate(csr, caCertificate, subjectKeyPair, caKey);
            ExportCrt(signedCertificate, "signed2.crt");
            ExportPfx(signedCertificate, "signed2.pfx");
        }


        public static void ExportPfx(X509Certificate2 certificate, string fileName)
        {
            byte[] certBytes = certificate.Export(X509ContentType.Pfx);

            FileStream fs = new FileStream(fileName, FileMode.CreateNew);
            fs.Write(certBytes, 0, certBytes.Length);
            fs.Flush();
            fs.Close();
        }

        public static void ExportCrt(X509Certificate2 certificate, string fileName)
        {
            byte[] certBytes = certificate.Export(X509ContentType.Cert);

            FileStream fs = new FileStream(fileName, FileMode.CreateNew);
            fs.Write(certBytes, 0, certBytes.Length);
            fs.Flush();
            fs.Close();
        }

        public static AsymmetricKeyParameter GetPrivateKeyFromKeyFile(string key)
        {
            StreamReader key_sr = new StreamReader(key);
            PemReader key_pr = new PemReader(key_sr);
            var keyPair = key_pr.ReadObject();

            AsymmetricKeyParameter keyParam;
            AsymmetricCipherKeyPair cipher = keyPair as AsymmetricCipherKeyPair;
            if (cipher != null)
                keyParam = cipher.Private;
            else keyParam = keyPair as AsymmetricKeyParameter;
            return keyParam;
        }
        public static Pkcs10CertificationRequest GenerateCsr(IDictionary attributes, out AsymmetricCipherKeyPair subjectKP)
        {
            var kpgen = new RsaKeyPairGenerator();

            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);
            var keyGenerationParameters = new KeyGenerationParameters(random, 2048);

            kpgen.Init(keyGenerationParameters);
            AsymmetricCipherKeyPair subjectKeyPair = default(AsymmetricCipherKeyPair);
            subjectKeyPair = kpgen.GenerateKeyPair();
            AsymmetricCipherKeyPair issuerKeyPair = subjectKeyPair;
            ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA512WITHRSA", issuerKeyPair.Private, random);

            X509Name subject = new X509Name(new ArrayList(attributes.Keys), attributes);

            Pkcs10CertificationRequest result = new Pkcs10CertificationRequest(signatureFactory, subject,
                subjectKeyPair.Public, null);

            subjectKP = subjectKeyPair;
            return result;
        }

        public static X509Certificate2 GetSignedCertificate(Pkcs10CertificationRequest csr,
            X509Certificate2 caCertificate, AsymmetricCipherKeyPair subjectKeyPair,
            string keyFile)
        {
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);
            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

            BigInteger serialNumber =
                BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), random);

            certGen.SetSerialNumber(serialNumber);
            certGen.SetIssuerDN(CreateIssuerName(caCertificate.IssuerName));
            certGen.SetNotBefore(DateTime.Today.Subtract(new TimeSpan(1, 0, 0, 0)));
            certGen.SetNotAfter(DateTime.Today.AddDays(1000));
            certGen.SetSubjectDN(csr.GetCertificationRequestInfo().Subject);
            certGen.SetPublicKey(csr.GetPublicKey());

            AsymmetricKeyParameter privateKey = GetPrivateKeyFromKeyFile(keyFile);

            ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA256WITHRSA", privateKey, random);

            Org.BouncyCastle.X509.X509Certificate certificate = certGen.Generate(signatureFactory);

            var store = new Pkcs12Store();
            string friendlyName = certificate.SubjectDN.ToString();
            var certificateEntry = new X509CertificateEntry(certificate);
            store.SetCertificateEntry(friendlyName, certificateEntry);
            store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(subjectKeyPair.Private), new[] { certificateEntry });
            var stream = new MemoryStream();
            store.Save(stream, "".ToCharArray(), random);
            var convertedCertificate = new X509Certificate2(stream.ToArray(), "",
                X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

            return convertedCertificate;
        }

        public static X509Certificate2 ReadCertificateFromPemFiles(string crt, string key)
        {
            var splPath = crt.Split(new char[] { '\\', '/' });
            string name = splPath[splPath.Count() - 1];
            StreamReader cert_sr = new StreamReader(crt);
            PemReader cert_pr = new PemReader(cert_sr);
            Org.BouncyCastle.X509.X509Certificate cert = (Org.BouncyCastle.X509.X509Certificate)cert_pr.ReadObject();

            StreamReader key_sr = new StreamReader(key);
            PemReader key_pr = new PemReader(key_sr);
            var keyPair = key_pr.ReadObject();

            AsymmetricKeyParameter keyParam;
            AsymmetricCipherKeyPair cipher = keyPair as AsymmetricCipherKeyPair;
            if (cipher != null)
                keyParam = cipher.Private;
            else keyParam = keyPair as AsymmetricKeyParameter;

            var store = new Pkcs12Store();
            string friendlyName = cert.SubjectDN.ToString();
            var certificateEntry = new X509CertificateEntry(cert);
            store.SetCertificateEntry(friendlyName, certificateEntry);
            store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(keyParam), new[] { certificateEntry });

            var stream = new MemoryStream();
            store.Save(stream, "".ToArray(), new SecureRandom());

            var convertedCertificate = new X509Certificate2(stream.ToArray(), "", X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

            return convertedCertificate;
        }


        public static X509Name CreateIssuerName(X500DistinguishedName name)
        {
            IList orderedAttributes = new ArrayList();
            orderedAttributes.Add(X509Name.E);
            orderedAttributes.Add(X509Name.CN);
            orderedAttributes.Add(X509Name.O);
            orderedAttributes.Add(X509Name.C);
            orderedAttributes.Add(X509Name.ST);
            orderedAttributes.Add(X509Name.OU);
            orderedAttributes.Add(X509Name.L);

            IDictionary attributes = new Hashtable();
            attributes[X509Name.E] = string.Empty;
            attributes[X509Name.CN] = string.Empty;
            attributes[X509Name.O] = string.Empty;
            attributes[X509Name.C] = string.Empty;
            attributes[X509Name.ST] = string.Empty;
            attributes[X509Name.OU] = string.Empty;
            attributes[X509Name.L] = string.Empty;
            var splitName = name.Name.Split(",".ToCharArray());
            foreach (var param in splitName)
            {
                var res = param.Split('=');
                switch (res[0].Trim())
                {
                    case "E":
                        attributes[X509Name.E] = res[1].Trim();
                        break;
                    case "CN":
                        attributes[X509Name.CN] = res[1].Trim();
                        break;
                    case "O":
                        attributes[X509Name.O] = res[1].Trim();
                        break;
                    case "C":
                        attributes[X509Name.C] = res[1].Trim();
                        break;
                    case "ST":
                        attributes[X509Name.ST] = res[1].Trim();
                        break;
                    case "OU":
                        attributes[X509Name.OU] = res[1].Trim();
                        break;
                    case "L":
                        attributes[X509Name.L] = res[1].Trim();
                        break;
                }
            }

            return new X509Name(orderedAttributes, attributes);
        }
        public static X509Certificate2 GenerateCertificate(IDictionary attributes)
        {
            IList orderedAttributes = new ArrayList();
            orderedAttributes.Add(X509Name.E);
            orderedAttributes.Add(X509Name.CN);
            orderedAttributes.Add(X509Name.O);
            orderedAttributes.Add(X509Name.C);
            orderedAttributes.Add(X509Name.ST);
            orderedAttributes.Add(X509Name.OU);
            orderedAttributes.Add(X509Name.L);

            var kpgen = new RsaKeyPairGenerator();

            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);
            AsymmetricCipherKeyPair subjectKeyPair = default(AsymmetricCipherKeyPair);
            var keyGenerationParameters = new KeyGenerationParameters(random, 2048);

            kpgen.Init(keyGenerationParameters);
            subjectKeyPair = kpgen.GenerateKeyPair();
            AsymmetricCipherKeyPair issuerKeyPair = subjectKeyPair;
            ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA512WITHRSA", issuerKeyPair.Private, random);

            var cerKp = kpgen.GenerateKeyPair();

            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

            certGen.SetSerialNumber(BigInteger.One);
            certGen.SetIssuerDN(new X509Name(orderedAttributes, attributes));
            certGen.SetNotBefore(DateTime.Today.Subtract(new TimeSpan(1, 0, 0, 0)));
            certGen.SetNotAfter(DateTime.Today.AddDays(1000));
            certGen.SetSubjectDN(new X509Name(orderedAttributes, attributes));
            certGen.SetPublicKey(cerKp.Public);
            certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, true,
                new AuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(cerKp.Public)));

            var certificate = certGen.Generate(signatureFactory);

            var store = new Pkcs12Store();
            string friendlyName = certificate.SubjectDN.ToString();
            var certificateEntry = new X509CertificateEntry(certificate);
            store.SetCertificateEntry(friendlyName, certificateEntry);
            store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(subjectKeyPair.Private), new[] { certificateEntry });
            var stream = new MemoryStream();
            store.Save(stream, "".ToCharArray(), random);
            var convertedCertificate = new X509Certificate2(stream.ToArray(), "",
                X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

            //X509Certificate initialCert = DotNetUtilities.ToX509Certificate(certificate);
            //X509Certificate2 cert = new X509Certificate2(initialCert);

            return convertedCertificate;
        }
    }
}
