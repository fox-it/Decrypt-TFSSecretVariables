# Decrypt-TFSSecretVariables

Within Team Foundation Server (TFS), it is possible to automate the build, testing and deployment of new releases. With the use of variables it is possible to create a generic deployment process once and customize it per environment. Sometimes specific tasks need a set of credentials or other sensitive information and therefor TFS supports encrypted variables. 
With an encrypted variable the contents of the variables is encrypted in the database and not visible for the user of TFS.
However, with the correct amount of access rights to the database it is possible to decrypt the encrypted content. Sebastian Solnica wrote a blogpost about this, which can be read on the following link: https://lowleveldesign.org/2017/07/04/decrypting-tfs-secret-variables/

This PowerShell script uses the information mentioned in the blogpost. While the blogpost mainly focused on the decryption technique, the PowerShell script is built with usability in mind. The script will query all needed values and display the decrypted values. 

Usage:

```
    This tool can be used to decrypt TFS variables. 
    More information: https://blog.fox-it.com/2018/05/17/introducing-team-foundation-server-decryption-tool/

    Required parameters:
        databaseServer  : DatabaseServer. <localhost\SQLEXPRESS>
        database        : Name of the database. Defaults to Tfs_DefaultCollection
  
    Optional parameters:
        dbaUsername     : DBA Username
        dbaPassword     : DBA Password
        secret          : encrypted data
        cspBlob         : private key


    The tool will use integrated authentication, unless dbaUsername and dbaPassword are specified.
    To decrypt values manually, use the secret and cspblob parameters 

    Usage: ./Decrypt-TFSSecretVariables.ps1 -databaseServer <location>
    
```
