# ecdsa-bug-jlink

When using jlink and jpackage, in combination with signed jars, the SunEC Provider isn't loaded and any application 
requiring a Signature verification operation with algorithms such as SHA256withECDSA, SHA384withECDSA or SHA512withECDSA
throws a failure (see the output.log file in this repository for an an example).

The bug doesn't show up when the jars aren't signed.

Steps to reproduce the issue:

1. run `mvn clean install`
    - be sure that you define in your maven settings.xml profile the following fields (or in the pom.xml):
     ```xml
       <properties>
           <codesign.keystore>MYKEYSTORE.p12</codesign.keystore>
           <codesign.keystore.alias>MYALIAS</codesign.keystore.alias>
           <codesign.keystore.password>MYPASSWORD</codesign.keystore.password>
        </properties>
     ```

2. run the following command:
```bash
./jpackage-builder/target/workspace/redist/signature-verifier/bin/signature-verifier \
    -t jpackage-builder/src/main/resources/truststore.p12 \
    -f PKCS12 \
    -a SHA384withECDSA \
   jpackage-builder/src/main/resources/testfile.txt \
   jpackage-builder/src/main/resources/testfile.txt.sig
```

As example, there's a truststore.jks with public certificates to verify the code.
The signed object is obtained using `openssl` command line tool like this:

```bash
openssl dgst -sha384 -sign "${codesign.keystore} -passin pass:${codesign.keystore.password} \
        -keyform p12 \
        -out ${project.basedir}/src/main/resources/testfile.txt.sig \
        ${project.basedir}/src/main/resources/testfile.txt
```

If you like to use Docker, then you can build everything by issueing the following command:

```bash
docker run --rm -it -v $(pwd):/project -w /project maven:3-jdk-14 mvn clean install
```