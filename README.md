# Custom Components

This Maven project contains three custom components

1.  application-registration :  To bypass generating consumer key, consumer secret keys after creating API Manager 
                                internal  OAuth Application
                                
2. jwt-custom-claims         :  To send the external OAuth Principle to backend

3. keymanager                :  To connect external OAuth Server and retrieve token and validate the token in runtime
    

## Required Software
1. JAVA
2. MAVEN


## How to build
 Execute the following command from parent directory
 - mvn clean install
 
 
All three JARS should be copied to <APIM_HOME>/repository/components/lib directory.