Welcome to Data Guardian version 1.0.0
To run the program install a python IDE and install the depencies found at the top of each file


Please read the in program readme before using and use at your own risk

Once I figure out why I am getting errors when I build it into an .exe I will include it in the repository :)


Overview


Data Guardian is a robust encryption tool designed to safeguard your data using both symmetric (single key) and asymmetric encryption (private and public keys).
By using Data Guardian, you can ensure the security of your sensitive data with state-of-the-art encryption technology and multiple layers of security.
After creating an account, you will gain access to a personal vault for encrypting and decrypting files.
Credentials are securely stored locally in the program's main directory. The user is responsible for managing the private key, once it is created this key should be removed from the main directory and stored securely.   
The overall security of the system heavily relies on the confidentiality of your private key. It is crucial to keep this key secure and private.

Accessing the Vault


To access your vault, you need to provide your private key, encrypted symmetric key, and your login credentials (username and password).
Once access is granted, you can encrypt and decrypt files as needed.
The encryption and decryption processes utilize the symmetric key, which is automatically decrypted during login and remains vulnerable only during the program's usage.


Security Layers 

Username and Password: The first layer of security is your username and password. These credentials 
are hashed using the Blowfish encryption algorithm (Bcrypt) and securely stored in the shadow.txt file.

Encryption Keys: Upon account creation, three essential keys are generated and stored in the Data_Guardian directory folder: 

Symmetric Key: Used for encrypting and decrypting your files. Public Key: Used to encrypt the symmetric key for 
secure storage. 

Private Key: The only key that can decrypt the symmetric key, and other data encrypted by the public.


WARNING


Storage Caution: Avoid storing the private key on the same computer as the application to mitigate the risk of unauthorized access in case of a security breach.
Loss of Access: Losing access to your private key or symmetric key means permanent inaccessibility to your data. It is vital to take necessary precautions.

Recommendations


External Storage: For enhanced security, consider saving your keys to an external USB drive, hard drive, or other storage media.
Key Copies: Evaluate the advantages and risks of creating multiple copies of your private and symmetric keys.


