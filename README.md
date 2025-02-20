# sso-saml-idp-server
This repository provides a comprehensive example of how to implement a SAML Identity Provider (IdP) for Single Sign-On (SSO) authentication. It demonstrates the key concepts and functionalities required to set up a SAML IdP, including metadata generation, SAML assertions, and integration with Service Providers (SP) using GO

## SSO Flow

![sso flow](https://user-images.githubusercontent.com/39133739/93079962-9e5d2880-f6aa-11ea-9521-feee3d4b4151.png)


## Setup idp private and public key

First please copy this line and run it into root repository

    openssl req -newkey rsa:2048 -new -x509 -days 365 -nodes -out idp-cert.pem -keyout idp-key.pem

## Setup env file

Rename **.env.example** file with **.env** and don't forget to edit the values

    BASE_URL={IDP BASE URL}    
    ASSERT_URL={SP ENDPOINT TO RECEIVE SAML RESPONSE}
    SP_ENTITY_URL={SP METADATA URL}
    SAML_RESPONSE_LIMIT_MINUTES={HOW MANY MINUTES SAML RESPONSE LAST}
    PORT={SERVER PORT}


## Run Program

Run the program using this line:

    go run main.go