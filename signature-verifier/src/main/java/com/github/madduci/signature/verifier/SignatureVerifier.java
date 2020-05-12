package com.github.madduci.signature.verifier;


import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * @author m_adduci
 * created on May 12, 2020
 */
public class SignatureVerifier
{

  public SignatureVerifier()
  {
  }


  /**
   * Parses command line arguments and returns a namespace holding all the values.
   *
   * @param args the CLI arguments passed
   * @return the namespace
   */
  public Namespace parseArguments( final String[] args )
  {
    ArgumentParser parser = ArgumentParsers.newFor( SignatureVerifier.class.getSimpleName() ).build()
                                           .defaultHelp( true )
                                           .description( "Verify the signature of given file." );
    parser.addArgument( "-t", "--truststore" ).help( "The truststore where the certificate is stored" );
    parser.addArgument( "-p", "--trustpassword" ).setDefault( "" ).help( "The truststore password" );
    parser.addArgument( "-f", "--format" ).choices( "JKS", "PKCS12" ).setDefault( "JKS" ).help( "The truststore format" );
    parser.addArgument( "-a", "--algorithm" ).choices( "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA" ).setDefault( "SHA256withECDSA" )
          .help( "The hash algorithm" );
    parser.addArgument( "file" ).nargs( 2 )
          .help( "Original file and signed file to look for the signature" );

    Namespace ns = null;
    try
    {
      ns = parser.parseArgs( args );
    }
    catch( ArgumentParserException e )
    {
      parser.handleError( e );
      System.exit( 1 );
    }

    return ns;
  }


  /**
   * Loads all the certificates stored in the supplied file.
   *
   * @return the list of loaded certificates
   * @throws KeyStoreException
   * @throws IOException
   * @throws NoSuchAlgorithmException
   * @throws CertificateException
   */
  public List<Certificate> loadCertificatesFromStore( final String storeType, final String storePath, final String storePassword )
    throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException
  {
    if( storeType == null || storePath == null || storePassword == null )
    {
      throw new KeyStoreException( "No valid input parameter given. Please, specify keystore type, keystore path and keystore password" );
    }

    if( storeType.isEmpty() || storePath.isEmpty() )
    {
      throw new KeyStoreException( "Store type and path cannot be empty." );
    }

    final KeyStore signTrustStore = KeyStore.getInstance( storeType );
    signTrustStore.load( new FileInputStream( storePath ), storePassword.toCharArray() );
    Enumeration<String> storeAliases = signTrustStore.aliases();

    List<Certificate> certificates = new ArrayList<>();
    // Check defined aliases are in the store and then load them
    while( storeAliases.hasMoreElements() )
    {
      final String storeEntry = storeAliases.nextElement();
      Certificate certificate = signTrustStore.getCertificate( storeEntry );
      if( certificate != null && signTrustStore.isCertificateEntry( storeEntry ) )
      {
        certificates.add( certificate );
      }
    }

    if( certificates.isEmpty() )
    {
      throw new KeyStoreException( "Could not find any valid certificate in the given keystore" );
    }

    return certificates;
  }


  /**
   * Verifies the signature of a given input data and signature object.
   *
   * @param inputData       the input data to be verified
   * @param inputSignedData the signed object used for the comparison
   * @param hashAlgorithm   the hash algorithm used for the signature
   * @throws SignatureException       in case of signature errors
   * @throws InvalidKeyException      in case of invalid public key
   * @throws NoSuchAlgorithmException in case of invalid hash algorithm
   */
  public void verify( final List<Certificate> certificates, final byte[] inputData, final byte[] inputSignedData, final String hashAlgorithm )
    throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
  {
    for( Certificate certificate : certificates )
    {
      System.out.println( "Using " + ( ( X509Certificate ) certificate ).getIssuerDN().getName() );
      PublicKey publicKey = certificate.getPublicKey();
      Signature signature = Signature.getInstance( hashAlgorithm );
      signature.initVerify( publicKey );
      signature.update( inputData );
      if( signature.verify( inputSignedData ) )
      {
        System.out.println( "Secure Boot digital signature verified successfully with " + ( ( X509Certificate ) certificate ).getSubjectDN().getName() );
        return;
      }
    }

    throw new SignatureException( "Invalid digital signature detected" );
  }


  public static void main( final String[] args )
  {
    final SignatureVerifier signatureVerifier = new SignatureVerifier();
    final Namespace ns = signatureVerifier.parseArguments( args );

    // Get files
    final List<String> inputFiles = ns.getList( "file" );

    try
    {
      final List<Certificate> certificates = signatureVerifier
        .loadCertificatesFromStore( ns.getString( "format" ), ns.getString( "truststore" ), ns.getString( "trustpassword" ) );

      final byte[] originalData = Files.readAllBytes( Paths.get( inputFiles.get( 0 ) ) );
      final byte[] signedData = Files.readAllBytes( Paths.get( inputFiles.get( 1 ) ) );

      signatureVerifier.verify( certificates, originalData, signedData, ns.getString( "algorithm" ) );

    }
    catch( Throwable t )
    {
      System.out.println( t.getLocalizedMessage() );
      t.printStackTrace();
      System.exit( 2 );
    }
  }

}
