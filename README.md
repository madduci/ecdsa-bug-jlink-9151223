# ecdsa-bug-jlink

When using jlink and jpackage, in combination with signed jars, the SunEC Provider isn't loaded and any application 
requiring a Signature verification operation with algorithms such as SHA256withECDSA, SHA384withECDSA or SHA512withECDSA
throws a failure (see the output.log file in this repository for an an example).

The bug doesn't show up when the jars aren't signed.

Steps to reproduce the issue:

1. run `mvn clean install`
    - be sure that you define in your maven settings.xml profile the following fields (or in the pom.xml):
     ```
       <properties>
           <codesign.keystore>MYKEYSTORE.p12</codesign.keystore>
           <codesign.keystore.alias>MYALIAS</codesign.keystore.alias>
           <codesign.keystore.password>MYPASSWORD</codesign.keystore.password>
        </properties>
     ```

2. run the following command:
```
./jpackage-builder/target/workspace/redist/signature-verifier/bin/signature-verifier \
    -t jpackage-builder/src/main/resources/truststore.jks \
    -f JKS \
    -a SHA384withECDSA \
   jpackage-builder/src/main/resources/testfile.txt \
   jpackage-builder/src/main/resources/testfile.txt.sig
```

As example, there's a truststore.jks with public certificates to verify the code.
The signed object is created using openssl like this:

```
openssl dgst -sha384 -sign "${codesign.keystore} -passin pass:${codesign.keystore.password} \
        -keyform p12 \
        -out ${project.basedir}/src/main/resources/testfile.txt.sig \
        ${project.basedir}/src/main/resources/testfile.txt
```