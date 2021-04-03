package implementation;
import java.security.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.math.BigInteger;
import java.security.KeyStore.Entry;
import java.security.KeyStore.Entry.Attribute;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.SecretKeyEntry;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
//import java.security.cert.Extension;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Vector;
import java.security.interfaces.*;

import javax.security.auth.x500.X500Principal;
import javax.swing.text.html.parser.Entity;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
//import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import code.GuiException;
import gui.Constants;
import code.*;
import x509.v3.*;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;


//main class: code.x509
public class MyCode extends CodeV3 {
   KeyStore keyStore;
   char[] password="root".toCharArray();
    private static final boolean keyCnt = true;
    org.bouncycastle.pkcs.PKCS10CertificationRequest cerRequestBuilder=null;

	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
		super(algorithm_conf, extensions_conf, extensions_rules);
	}
	//BouncyCastleProvider je morao staticki da se napravi jer drugacije nije htelo-pogledaj na programcreeku kako drugacije da napravis
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}

	@Override
	public boolean canSign(String keypair_name) {
		X509Certificate cert = null;
		try {
			 cert = (X509Certificate) keyStore.getCertificate(keypair_name);
			 boolean [] keyUsageVector=cert.getKeyUsage();
		        if( keyUsageVector != null && keyUsageVector[5] || cert.getBasicConstraints() != -1)
		        	return true;
			 else return false;
		} catch (KeyStoreException e) {
			access.reportError(e);
			e.printStackTrace();
		}
		return true;
		
	}

	@Override
	public boolean exportCSR(String file, String keypair_name, String algorithm) {
	
		try {
			X509Certificate cert=(X509Certificate) keyStore.getCertificate(keypair_name);
			PrivateKey PK=(PrivateKey) keyStore.getKey(keypair_name,this.password);
			PublicKey PU = cert.getPublicKey();
			X500Principal subject = new X500Principal(getSubjectInfo(keypair_name));
			ContentSigner signGen = new JcaContentSignerBuilder(algorithm).build(PK);
			PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, PU);
			cerRequestBuilder = builder.build(signGen);
			JcaPEMWriter out = new JcaPEMWriter(new FileWriter(file));
			out.writeObject(cerRequestBuilder);
			out.flush();
			out.close();
			return true;
		} catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException | OperatorCreationException | IOException e) {
			access.reportError(e);
			e.printStackTrace();
			return false;
		}
		
		
	}

	@Override
	public boolean exportCertificate(String file, String keypair_name, int encoding, int format) {
		try {
			File fileStore=new File(file);
			FileOutputStream f=new FileOutputStream(fileStore);
			if(format==0) {
				//Jedan certifikat(Head only)
				X509Certificate cert=(X509Certificate) keyStore.getCertificate(keypair_name);
				if(encoding==1) {
					//DER kodiranje - binarno kodiranje
					f.write(cert.getEncoded());
				}
				else {
					//PEM kodiranje - ASCII(Base64) kodiranje
					byte[] niz=cert.getEncoded();
					//Mora ovo da se doda na pocetku jer tako se oznacava naziv ovog kodiranja:https://support.ssl.com/Knowledgebase/Article/View/19/0/der-vs-crt-vs-cer-vs-pem-certificates-and-how-to-convert-them
					f.write("-----BEGIN CERTIFICATE-----\n".getBytes());
					f.write(Base64.getEncoder().encode(niz));
					f.write("-----END CERTIFICATE-----\n".getBytes());
				}
			}
			else {//Izvozimo ceo lanac sertifikata:
				X509Certificate[] certChain = (X509Certificate[]) keyStore.getCertificateChain(keypair_name);
				 if(certChain!=null)
				 for(int i=0;i<certChain.length;i++) {
					 f.write(Base64.getEncoder().encode(certChain[i].getEncoded()));
				 }
				 else {
					 X509Certificate certExp = (X509Certificate) keyStore.getCertificate(keypair_name);
					 f.write("-----BEGIN CERTIFICATE-----\n".getBytes());
					 f.write(Base64.getEncoder().encode(certExp.getEncoded()));
					 f.write("-----END CERTIFICATE-----\n".getBytes());
				 }
			}
			if(fileStore.getName().contains(".der")||fileStore.getName().contains(".pem")||fileStore.getName().contains(".crt")) {
				 access.reportError("Ne mogu se izvoziti fajlovi sa drugim extenzijama razlicitim od .cer");
				 return false;
			 }
			
			
		} catch (KeyStoreException | CertificateEncodingException | IOException e) {
			access.reportError(e);
			e.printStackTrace();
			return false;
		}
		
		return true;
	}

	@Override
	public boolean exportKeypair(String keypair_name,String file,  String password) {
		File fileF = new File(file);
		OutputStream OS = null;
		
		try {
			OS = new FileOutputStream(fileF);
			//Ako ne postoji ulaz u keyStoru sa datim alijasom
			if(!keyStore.isKeyEntry(keypair_name)) 
				return false;
			//Sve ulaze sam stitio istim paswordom (this.password)
			Entry entry = keyStore.getEntry(keypair_name, new KeyStore.PasswordProtection(this.password));
			PrivateKeyEntry  pkentry = (PrivateKeyEntry)entry ;
			KeyStore exportks = KeyStore.getInstance("pkcs12");
			exportks.load(null, null);
			java.security.cert.Certificate[] chain=keyStore.getCertificateChain(keypair_name);
			exportks.setKeyEntry(keypair_name, keyStore.getKey(keypair_name, this.password), password.toCharArray(), chain);
			exportks.store(OS, password.toCharArray());
			return true;
		} catch (  KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException | CertificateException | IOException e) {
			access.reportError(e);
			e.printStackTrace();
			return false;
		}
		
	}

	@Override
	public String getCertPublicKeyAlgorithm(String name) {
		try {
			X509Certificate cert = (X509Certificate) this.keyStore.getCertificate(name);
			String algorithm= cert.getPublicKey().getAlgorithm();
			return algorithm;
		} catch (KeyStoreException e) {
			
			e.printStackTrace();
		}
		
		return null;
	}

	@Override
	public String getCertPublicKeyParameter(String keypair_name) {
		String ret = new String("");
		try {
			PublicKey pk = keyStore.getCertificate(keypair_name).getPublicKey();
			String alg = pk.getAlgorithm();
			if (alg.equals("EC"))
				ret = ((ECPublicKey) pk).getParams().getCurve().toString();
			else if (alg.equals("DSA"))
				ret += ((DSAPublicKey) pk).getY().bitLength();
			else if (alg.equals("RSA"))
				ret += ((RSAPublicKey) pk).getModulus().bitLength();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return ret;
	}

	@Override
	public String getSubjectInfo(String keypair_name) {
		try {
			X509Certificate cert=(X509Certificate) keyStore.getCertificate(keypair_name);
			/*
			 * string name= access.getSubject(certificate.getSubjectDN().toString().replaceAll(", ", ",").replaceAll(",", " ,"));
			 */
			String name=cert.getSubjectX500Principal().getName();
			return name;
		} catch (KeyStoreException e) {
			access.reportError(e);
			e.printStackTrace();
			return null;
		}
		
		
	}

	@Override
	public boolean importCAReply(String file, String keypair_name) {
		/*File fileIn = new File(file);
		InputStream is = null;
		try {
			is = new FileInputStream(fileIn);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		CertificateFactory kolekcija = null;
		try {
			kolekcija = CertificateFactory.getInstance("X.509");
			Collection<X509Certificate> sert =  (Collection<X509Certificate>) kolekcija.generateCertificates(is);
			Iterator<X509Certificate> iter = sert.iterator();
			X509Certificate[] chain = new X509Certificate[sert.size()];
			int i=0;
			while(iter.hasNext()) {
				chain[i++]=iter.next();
			}*/
		try {
			FileInputStream in = new FileInputStream(new File(file));
			CertificateFactory fact = CertificateFactory.getInstance("X509");
			Collection<X509Certificate> coll = (Collection<X509Certificate>) fact.generateCertificates(in);
			Iterator<X509Certificate> it = (Iterator<X509Certificate>) coll.iterator();
			PrivateKey PR = (PrivateKey) keyStore.getKey(keypair_name, password);
			//Potpisani sertifikat i onaj koji ga je potpisao:
			X509Certificate[] chain = new X509Certificate[2];
			chain[0] = it.next();
			chain[1] = it.next();
			keyStore.setKeyEntry(keypair_name, PR, password, chain);
			saveKeyStore();
			loadKeypair(keypair_name);
		} catch (FileNotFoundException | CertificateException | UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
			access.reportError(e);
			e.printStackTrace();
		}
		
		
		
		
		
		
		
		return true;
	}

	@Override
	public String importCSR(String file) {
	//NAPOMENA * NIJE TI ISTA IMPLEMENTACIJA KAO SA BOUNCYCASTLEA PA MOZDA CERTREGUEST BUILDER BUDE ZEZAO 
		org.bouncycastle.pkcs.PKCS10CertificationRequest tempCsr = null;
		StringBuilder ret = new StringBuilder("");
		//FileInputStream IS=new FileInputStream(file);
		Reader pemReader;
		try {
			pemReader = new BufferedReader(new InputStreamReader(new FileInputStream(file)));
			PEMParser pemParser = new PEMParser(pemReader);
			Object parsedObj = pemParser.readObject();
			
			if (parsedObj instanceof org.bouncycastle.pkcs.PKCS10CertificationRequest) {
				tempCsr = (org.bouncycastle.pkcs.PKCS10CertificationRequest) parsedObj;
			}
			pemParser.close();
			pemReader.close();
			if (tempCsr == null)
				return null;
			cerRequestBuilder = tempCsr;
        
			X500Name sub = cerRequestBuilder.getSubject();
			//Moras da radis replacovanje jer je GUI tako podesen - vidi se kad pozoves decompiler za njihov jar file
			return cerRequestBuilder.getSubject().toString().replaceAll(", ", ",").replaceAll(",", " ,");
			/*
			boolean flag = false;

			for (RDN tmp : sub.getRDNs()) {
				AttributeTypeAndValue t = tmp.getFirst();
				ASN1ObjectIdentifier tt = t.getType();
				ASN1Encodable tv = t.getValue();

				if (tt == BCStyle.CN.intern())
					ret.append((flag ? "," : "") + "CN=");
				else if (tt == BCStyle.C.intern())
					ret.append((flag ? "," : "") + "C=");
				else if (tt == BCStyle.L.intern())
					ret.append((flag ? "," : "") + "L=");
				else if (tt == BCStyle.O.intern())
					ret.append((flag ? "," : "") + "O=");
				else if (tt == BCStyle.ST.intern())
					ret.append((flag ? "," : "") + "ST=");
				else if (tt == BCStyle.OU.intern())
					ret.append((flag ? "," : "") + "OU=");
				ret.append(tv.toString());
				flag = true;
			}*/
		    
		} catch (IOException e) {
			access.reportError(e);
			e.printStackTrace();
		}
		
		
		return ret.toString();
	}

	@Override
	public boolean importCertificate(String file, String keypair_name) {
	File f=new File(file);
	try {
		FileInputStream fis=new FileInputStream(f);
		CertificateFactory cf=CertificateFactory.getInstance("X509");
		//X509Certificate cert=(X509Certificate) cf.generateCertificate(fis);
		//java.security.cert.Certificate cert=cf.generateCertificate(fis);
		X509Certificate c= (X509Certificate) cf.generateCertificate(fis);
		keyStore.setCertificateEntry(keypair_name, c);
		saveKeyStore();
		
		return true;
	} catch ( CertificateException | KeyStoreException |   IOException e) {
		access.reportError(e);
		e.printStackTrace();
		return false;
	}
		
	}

	@Override
	public boolean importKeypair(String keypair_name, String file, String password) {
		FileInputStream stream=null;
		try {
			stream=new FileInputStream(file);
			KeyStore ks=KeyStore.getInstance("PKCS12", "BC");
			ks.load(stream, password.toCharArray());
			stream.close();
			Enumeration<String> aliases = ks.aliases();
            if (!aliases.hasMoreElements()) {
                this.access.reportError(" Zadati fajl nema ni jedan par kljuceva u sebi");
                return false;
            }
            String alias = aliases.nextElement();
            //Dohvatamo privatni kljuc 
			Key key=ks.getKey(alias, password.toCharArray());
			//Dodajemo nov sertifikat i njegov odgovarajuci privatni kljuc u KeyStore
			keyStore.setKeyEntry(keypair_name, key, this.password,ks.getCertificateChain(alias));
            saveKeyStore();
			
			
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException  | IOException | UnrecoverableKeyException | NoSuchProviderException e) {
			
			access.reportError(e);
			e.printStackTrace();
			return false;
		}
		finally {
			
			if(stream!=null)
				try {
					stream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			
				
		}
		
		
		return true;
	}

	@Override
	public int loadKeypair(String arg0) {
		try {
			//Ispisivanje osnovnih podataka o sertifikatu
			X509Certificate certificate=(X509Certificate)	this.keyStore.getCertificate(arg0);
			this.access.setNotAfter(certificate.getNotAfter());
			this.access.setNotBefore(certificate.getNotBefore()); 
			this.access.setVersion(Constants.V3);
			this.access.setSerialNumber(certificate.getSerialNumber().toString());
			this.access.setPublicKeyAlgorithm(getCertPublicKeyAlgorithm(arg0));
			this.access.setPublicKeyParameter(getCertPublicKeyParameter(arg0));
			this.access.setPublicKeyDigestAlgorithm(certificate.getSigAlgName());
			this.access.setSubjectSignatureAlgorithm(certificate.getPublicKey().getAlgorithm());
		//  Ispisivanje podataka o vlasniku sertifikata
			//System.out.println(certificate.getIssuerDN().toString().replaceAll(", ", ",").replaceAll(",", " ,"));
			//access.setIssuer(certificate.getIssuerDN().toString().replaceAll(", ", ",").replaceAll(",", " ,"));
			System.out.println(certificate.getIssuerX500Principal().getName().replaceAll(",", " ,"));
			access.setIssuer(certificate.getIssuerX500Principal().getName().replaceAll(",", " ,"));
			access.setIssuerSignatureAlgorithm(certificate.getSigAlgName());
			//access.setSubject(certificate.getSubjectDN().toString().replaceAll(", ", ",").replaceAll(",", " ,"));
			System.out.println(certificate.getSubjectX500Principal().getName().replaceAll(",", " ,"));
			access.setSubject(certificate.getSubjectX500Principal().getName().replaceAll(",", " ,"));
			access.setSubjectSignatureAlgorithm(certificate.getPublicKey().getAlgorithm());
			JcaX509CertificateHolder holder=new JcaX509CertificateHolder(certificate);
			/*X500Name subject=holder.getSubject();
			for (RDN tmp : subject.getRDNs()) {
				AttributeTypeAndValue t = tmp.getFirst();
				ASN1ObjectIdentifier tt = t.getType();
				ASN1Encodable tv = t.getValue();

				if (tt == BCStyle.CN.intern())
					access.setSubjectCommonName(tv.toString());
				else if (tt == BCStyle.C.intern())
					access.setSubjectCountry(tv.toString());
				else if (tt == BCStyle.L.intern())
					access.setSubjectLocality(tv.toString());
				else if (tt == BCStyle.O.intern())
					access.setSubjectOrganization(tv.toString());
				else if (tt == BCStyle.ST.intern())
					access.setSubjectState(tv.toString());
				else if (tt == BCStyle.OU.intern())
					access.setSubjectOrganizationUnit(tv.toString());
			}
			*/
			//Stikliranje cekboxova ako je extenzija kriticna
			String keyUsageOID="2.5.29.15";
			String subjectAltrenativeNameOIDS="2.5.29.17";
			String inhibitAnyPolicy="2.5.29.54";
			if (certificate.getCriticalExtensionOIDs() != null) {
				for(String extension: certificate.getCriticalExtensionOIDs()) {
					if(extension.equals(keyUsageOID)) {
						this.access.setCritical(Constants.KU, true);
					}
					if(extension.equals(subjectAltrenativeNameOIDS)) {
						this.access.setCritical(Constants.SAN, true);
					}
					if(extension.equals(inhibitAnyPolicy)) {
						this.access.setCritical(Constants.IAP, true);
					}
				}
			}
			//ISPISIVANJE SADRZAJA EXTENZIJA:
			
			//1. ekst. key usage
			boolean[] keyUsage = certificate.getKeyUsage();
			if (keyUsage != null)
				access.setKeyUsage(certificate.getKeyUsage());
			//**PROVERIII***
			//2. ekst. subject alternative names:
			Collection<List<?>> SubjectAlternativeNames= certificate.getSubjectAlternativeNames();
			String[] niz=null; 
			
			if(SubjectAlternativeNames!=null) {
				
				List<String> newList = new ArrayList<String>(SubjectAlternativeNames.size()) ;
				for (List<?> myInt : SubjectAlternativeNames) { 
				  newList.add(String.valueOf(myInt)); 
				}
		
          
		for(String tmp:newList) {
			access.setAlternativeName(Constants.SAN, tmp);
		}
		
			}
			//3. ekst. inhibit any policy:
		
			Extension ext = holder.getExtension(Extension.inhibitAnyPolicy);
			if(ext !=null) {
				access.setInhibitAnyPolicy(true);
				access.setSkipCerts(ASN1Integer.getInstance(ext.getParsedValue()) + "");
			}
			
			//PROVERA DA LI JE SERTIFIKAT TRUSTED ILI JE POTPISAN
			
			boolean [] keyUsageVector=certificate.getKeyUsage();
	        if( keyUsageVector != null && keyUsageVector[5] || certificate.getBasicConstraints() != -1)
	        	return 2;
			if (!certificate.getSubjectDN().equals(certificate.getIssuerDN()))
				return 1;
			try {
				certificate.verify(certificate.getPublicKey());
				return 0;
			} catch (SignatureException | InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException e) {
				return 1;
			}
				/*if (!(new JcaX509CertificateHolder(certificate).getSubject().toString())
						.equals(new JcaX509CertificateHolder(certificate).getIssuer().toString()))
					{return 1;}
					*/
		} catch (KeyStoreException | CertificateEncodingException | CertificateParsingException e) {
			
			e.printStackTrace();
			return -1;
		}
	}

	@Override
	public Enumeration<String> loadLocalKeystore() {
		try {
			keyStore = KeyStore.getInstance("PKCS12", "BC");
			char[] pass = (password == null) ? "root".toCharArray() : password;
			try (FileInputStream input = new FileInputStream("localKeyStorage.p12")) {
                keyStore.load(input, pass);
            } catch (IOException e) {
                keyStore.load(null, pass);
                try (FileOutputStream output = new FileOutputStream("localKeyStorage.p12")) {
                    keyStore.store(output, pass);
                }
            }
			
			return keyStore.aliases();
		} catch (Exception e) {
			access.reportError(e);
			e.printStackTrace();
		}		return null;
	}

	@Override
	public boolean removeKeypair(String arg0) {
		  try {
			keyStore.deleteEntry(arg0);
			saveKeyStore();
		} catch (KeyStoreException e) {
			access.reportError(e);
			e.printStackTrace();
			return false;
		}
		return true;
	}

	@Override
	public void resetLocalKeystore() {
		try {
			Enumeration<String> aliases=this.keyStore.aliases();
			while(aliases.hasMoreElements()) {
				String str=aliases.nextElement();
				this.keyStore.deleteEntry(str);
			}
			saveKeyStore();
			
		} catch (KeyStoreException e) {
            access.reportError(e);			
			e.printStackTrace();
		}
		
	}

	@Override
	public boolean saveKeypair(String keypair_name) {
		// Ne znam zasto ovo mora staticki , ima na programcreeku : Security.addProvider(new BouncyCastleProvider()); 
		//Uslov za moju grupu je da verzija sertifikata mora biti 3 i da algoritam koji se koristi za generisanje kljuceva mora biti RSA
		if (access.getVersion() != Constants.V3)
			return false;
		if(access.getPublicKeyAlgorithm()!="RSA")
			return false;
		
		try {
			//GENERISANJE KLJUCA I KORISNICKI UNOS BEZ EXTENZIJA
			KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
			//Posto smo koristili Algorithm specified generisanje kljuca, generator se mora inicijalizovati
			g.initialize(Integer.parseInt(access.getPublicKeyParameter()));
			KeyPair keyPair=g.generateKeyPair();
			PublicKey publicKey=keyPair.getPublic();
			PrivateKey privateKey=keyPair.getPrivate();
			Date dateNotAfter=access.getNotAfter();
			Date dateNOtBefore=access.getNotBefore();
			BigInteger serial = new BigInteger(access.getSerialNumber());
			String name=access.getSubjectCommonName();
			String country=access.getSubjectCountry();
			String locality=access.getSubjectLocality();
			String organisationUnit=access.getSubjectOrganizationUnit();
			String organisation=access.getSubjectOrganization();
			String state=access.getSubjectState();
			X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
			nameBuilder.addRDN(BCStyle.O, organisation);
			nameBuilder.addRDN(BCStyle.OU, organisationUnit);
			nameBuilder.addRDN(BCStyle.ST, state);
			nameBuilder.addRDN(BCStyle.L, locality);
			nameBuilder.addRDN(BCStyle.C, country);
			nameBuilder.addRDN(BCStyle.CN, name);
			System.out.println(access.getSubject());
			//X500Name issuer = nameBuilder.build();
			//X500Name subject = issuer; // = nameBuilder.build();
			X500Principal subject=new X500Principal(access.getSubject());
			X500Principal issuer=subject;
			
		//Mogla je da se koristi i osnovna klasa:
			JcaX509v3CertificateBuilder builder =new JcaX509v3CertificateBuilder(issuer,serial,dateNOtBefore,dateNotAfter,subject,publicKey);
			//DODAVANJE EKSTENZIJA
			boolean[] keyUsage = access.getKeyUsage();
			boolean critical=access.isCritical(Constants.KU);
			int usage = 0;
			for (int i = 0; i < 9; i++) {
				if (keyUsage[i])
					switch (i) {
					case 0:
						usage |= KeyUsage.digitalSignature;
						break;
					case 1:
						usage |= KeyUsage.nonRepudiation;
						break;
					case 2:
						usage |= KeyUsage.keyEncipherment;
						break;
					case 3:
						usage |= KeyUsage.dataEncipherment;
						break;
					case 4:
						usage |= KeyUsage.keyAgreement;
						break;
					case 5:
						usage |= KeyUsage.keyCertSign;
						break;
					case 6:
						usage |= KeyUsage.cRLSign;
						break;
					case 7:
						usage |= KeyUsage.encipherOnly;
						break;
					case 8:
						usage |= KeyUsage.decipherOnly;
						break;
					}
			}
			KeyUsage ku= new KeyUsage(usage);
			builder.addExtension(Extension.keyUsage, critical,ku );
			
			boolean inhibit = access.getInhibitAnyPolicy();
			boolean criticalInhibit = access.isCritical(Constants.IAP);
			if(inhibit) {
				String skip_certs=access.getSkipCerts();
				int skipCerts;
				if (skip_certs.equals("") || skip_certs.charAt(0) == '-')
					skipCerts = Integer.MAX_VALUE;
				else
					skipCerts = Integer.parseInt(skip_certs);

				ASN1Integer Inhibitany = new ASN1Integer(skipCerts);
				builder.addExtension(Extension.inhibitAnyPolicy, criticalInhibit, Inhibitany);
			}
			
			
			
			List<String> newList;
			String[] names=access.getAlternativeName(Constants.SAN);
			boolean critical_Alternative=access.isCritical(Constants.SAN);
			List<GeneralName> altNames = new ArrayList<GeneralName>();
			String rfc822Regex = "(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])";
			String IPRegex="^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
			        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
			        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
			        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])$";
			String DNSRegex="^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,}$";
			if(names!=null) {
	        for(String tmp:names) {
	        	if(tmp.matches(rfc822Regex)) {
	        		altNames.add(new GeneralName(GeneralName.rfc822Name, tmp));
	        	}
	        	else {
	        		if(tmp.matches(IPRegex)) {
	        			 altNames.add(new GeneralName(GeneralName.iPAddress, tmp));
	        			
	        		}
	        		else {
	        			if(tmp.matches(DNSRegex)) {
	        				
	        				altNames.add(new GeneralName(GeneralName.dNSName, tmp));
	        			}
	        			else {
	        				access.reportError("Nevalidan unos za SAN");
	        				return false;
	        			}
	        		}
	        	}
	        	
	        }
	        GeneralNames subjectAltNames = GeneralNames.getInstance(new DERSequence((GeneralName[]) altNames.toArray(new GeneralName[] {})));
				/*Collection<List<?>> SubjectAlternativeNames=null;
				int a;
				for(String tmp:names) {
					a=Integer.parseInt(tmp);
					List<Integer> list=null;
					list.add(a);
					SubjectAlternativeNames.add(list);
				}
				*/
				builder.addExtension(Extension.subjectAlternativeName,critical_Alternative,subjectAltNames);
				//builder.add
				
			}
			
				
			//***NAPOMENA TI NISI RADIO SA NADKLASOM KLASE JCABUILDER NEGO SA TOM KLASOM STO SE RAZLIKUJE OD PRIMERA NA BOUNCYCASTLU
			//Nas sertifikat potpisuje samog sebe
			ContentSigner signer = new JcaContentSignerBuilder(access.getPublicKeyDigestAlgorithm()).build(privateKey);
			X509CertificateHolder holder = builder.build(signer);
			X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
			//U lancu je u stvari samo taj jedan sertifikat
			X509Certificate[] chain = new X509Certificate[1];
			chain[0] = cert;
           //U KEyStore se dodaje sertifikat chain koji je zasticen paswordom i odgovara privatnom kljucu kojim je i potpisan
			keyStore.setKeyEntry(keypair_name, privateKey, password, chain);
			saveKeyStore();
			
		} catch (NoSuchAlgorithmException | OperatorCreationException | CertificateException | KeyStoreException | CertIOException e) {
			access.reportError(e);
			e.printStackTrace();
		}
		
		
		
		return true;
	}

	@Override
	public boolean signCSR(String file, String keypair_name, String algorithm) {
		
		try {
			X509Certificate cert=(X509Certificate) keyStore.getCertificate(keypair_name);
			//izdavalac sertifikata:
			JcaX509CertificateHolder holder=new JcaX509CertificateHolder(cert);
			X500Name issuer=holder.getSubject();
			//podaci o sertifikatu korisnika:
			//Moglo je sve i da se dohvati iz cerRequestBuildera jer smo odatle i ispisali na ekran sa kog sada citamo ostale podatke
			X500Name subject=cerRequestBuilder.getSubject();
			BigInteger serial=new BigInteger(access.getSerialNumber());
			Date notBefore=access.getNotBefore();
			Date notAfter=access.getNotAfter();
		    SubjectPublicKeyInfo SPKY=	cerRequestBuilder.getSubjectPublicKeyInfo();
		    X509v3CertificateBuilder builder=new X509v3CertificateBuilder(issuer,serial,notBefore,notAfter,subject,SPKY);
		  //Dodavanje extenzija:
		    //...
		    
		 // key usage extenzija
		    
			boolean[] ku = access.getKeyUsage();
			boolean kuCrit = access.isCritical(Constants.KU);
			int usage = 0;
			if(ku!=null) {
				for (int i = 0; i < 9; i++) {
					if (ku[i])
						switch (i) {
						case 0:
							usage |= KeyUsage.digitalSignature;
							break;
						case 1:
							usage |= KeyUsage.nonRepudiation;
							break;
						case 2:
							usage |= KeyUsage.keyEncipherment;
							break;
						case 3:
							usage |= KeyUsage.dataEncipherment;
							break;
						case 4:
							usage |= KeyUsage.keyAgreement;
							break;
						case 5:
							usage |= KeyUsage.keyCertSign;
							break;
						case 6:
							usage |= KeyUsage.cRLSign;
							break;
						case 7:
							usage |= KeyUsage.encipherOnly;
							break;
						case 8:
							usage |= KeyUsage.decipherOnly;
							break;
						}
				}
				KeyUsage KU = new KeyUsage(usage);
				builder.addExtension(Extension.keyUsage, kuCrit, KU);
			}
			
			//inhibit any policy
		    /*
			boolean iap = access.getInhibitAnyPolicy();
			boolean iapCrit = access.isCritical(Constants.IAP);
			if (iap) {
				int skipCerts;
				if (access.getSkipCerts().equals("") || access.getSkipCerts().charAt(0) == '-')
					skipCerts = Integer.MAX_VALUE;
				else
					skipCerts = Integer.parseInt(access.getSkipCerts());

				ASN1Integer IAP = new ASN1Integer(skipCerts);
				builder.addExtension(Extension.inhibitAnyPolicy, iapCrit, IAP);
			}
			*/
			// subject alternative names
			
			
			
			
			List<String> newList;
			String[] names=access.getAlternativeName(Constants.SAN);
			boolean critical_Alternative=access.isCritical(Constants.SAN);
			List<GeneralName> altNames = new ArrayList<GeneralName>();
			String rfc822Regex = "(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])";
			String IPRegex="^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
			        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
			        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
			        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])$";
			String DNSRegex="^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,}$";
			if(names!=null) {
	        for(String tmp:names) {
	        	if(tmp.matches(rfc822Regex)) {
	        		altNames.add(new GeneralName(GeneralName.rfc822Name, tmp));
	        	}
	        	else {
	        		if(tmp.matches(IPRegex)) {
	        			 altNames.add(new GeneralName(GeneralName.iPAddress, tmp));
	        			
	        		}
	        		else {
	        			if(tmp.matches(DNSRegex)) {
	        				
	        				altNames.add(new GeneralName(GeneralName.dNSName, tmp));
	        			}
	        			else {
	        				access.reportError("Nevalidan unos za SAN");
	        				return false;
	        			}
	        		}
	        	}
	        	
	        }
	        GeneralNames subjectAltNames = GeneralNames.getInstance(new DERSequence((GeneralName[]) altNames.toArray(new GeneralName[] {})));
				
				/*Collection<List<?>> SubjectAlternativeNames=null;
				int a;
				for(String tmp:names) {
					a=Integer.parseInt(tmp);
					List<Integer> list=null;
					list.add(a);
					SubjectAlternativeNames.add(list);
				}
				*/
				
		         builder.addExtension(Extension.subjectAlternativeName,critical_Alternative,subjectAltNames);
				//builder.add
				
			}
			
		    //Potpisivanje sertifikata:
		   //Uzmi potpis:
		    ContentSigner signer = new JcaContentSignerBuilder(algorithm)
					.build((PrivateKey) keyStore.getKey(keypair_name, password));
           //Uzmi sadrzaj:
			byte[] encoded = builder.build(signer).getEncoded();
			//Napravi omotac oko novog napravljenog potpisanog sertifikata:
			X509CertificateHolder cHolder = new X509CertificateHolder(encoded);
             
			//Generisi generator pkcs7 potpisa 
			CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

			generator.addSignerInfoGenerator(
					new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(signer,
							(X509Certificate) keyStore.getCertificate(keypair_name)));

			generator.addCertificate(cHolder);

			 java.security.cert.Certificate[] caChain = keyStore.getCertificateChain(keypair_name);
			X509CertificateHolder CAHolder = null;
			//Prodji kroz ceo lanac sertifikata:
			for (java.security.cert.Certificate tmp : caChain) {
				CAHolder = new X509CertificateHolder(tmp.getEncoded());
				generator.addCertificate(CAHolder);
			}

			CMSSignedData data = generator.generate(new CMSProcessableByteArray(encoded), true);

			FileOutputStream out = new FileOutputStream(file);

			out.write(data.getEncoded());
			out.close();
			return true;
		    
		    
			
		} catch (KeyStoreException | CertificateEncodingException | OperatorCreationException | CMSException | IOException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
			access.reportError(e);
			e.printStackTrace();
			return false;
		}
		
		
	}
	
	private void saveKeyStore() {
		try {
			FileOutputStream out = new FileOutputStream("localKeyStorage.p12");
			keyStore.store(out, (password == null) ? "root".toCharArray() : password);
			out.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
