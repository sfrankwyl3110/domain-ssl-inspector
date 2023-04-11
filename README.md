# Domain SSL Inspector

### Description
Tests a domain periodically against the expiration of the SSL certificate

### Installation
``
pip install -r requirements.txt
``

### Config File
- domains.csv
  - content
    ```   
    domain,added,interval,last_check,last_expire_seconds
    whatsyourlanguage.world,0,600,0,0
    ```
     - domain
     - 0 - float added time.time
     - 600 - int interval in seconds
     - 0 - float last_check time.time
     - 0 - int last_expire_seconds
  - the zeros will  be replaced at execution
  
### Result example CSV
```
uuid,domain,subject,issuer,version,serialNumber,notBefore,notAfter,subjectAltName,OCSP,caIssuers,crlDistributionPoints,requested
34978750-2c27-40e3-a03a-c269684fc5f5,whatsyourlanguage.world,"((('commonName', 'whatsyourlanguage.world'),),)","((('countryName', 'US'),), (('organizationName', 'DigiCert Inc'),), (('organizationalUnitName', 'www.digicert.com'),), (('commonName', 'Encryption Everywhere DV TLS CA - G1'),))",3,0EC425B37588BF5DABC8EA6AE1167B91,Sep  4 00:00:00 2022 GMT,Sep  4 23:59:59 2023 GMT,"(('DNS', 'whatsyourlanguage.world'),)","('http://ocsp.digicert.com',)","('http://cacerts.digicert.com/EncryptionEverywhereDVTLSCA-G1.crt',)",,1681211708.4353426
```

### Author
Sascha Frank (sfrank@wyl-online.de)