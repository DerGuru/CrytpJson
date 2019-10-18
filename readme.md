When connecting to other systems, there is usually the need for some credentials and with them the question, how to store them safely.
Ask no longer, because the solution is here.

#.How does it work?
You will need need three parts for the whole thing to work.

1. A Certifcate with an accessible private key
2. Your derived class from CryptoJson (here: FooCredentials)
3. A BASE64 encoded asymmetrically encrypted JSON serialzed string, which you create from your own implementation once and then save somewhere.
You may also use binary encoded credentials, encoded as BSON.

Use `FooCredentials.Load(...)` to load your Credentials from your credential string.
This will create an instance of FooCredentials using the empty constructor.
It will further reverse the BASE64 encoding, JSON serialization and decrypts the whole thing into a new instance of FooCredentials and returns it four you to use.

#.Creating your own class
1) Derive your own class from the BASF.ExtensionLibrary.Security.CryptoJson<YourType>. 
There is the restriction, that the derived class MUST be self sustainable... which means, that ist must have an empty constructor and still be fully functional.
2) Keep in mind, that JSON reads and populates ALL public properties. So if you have some Properties, which should not be serialized, mark them with `[JsonIgnore]`.
3) Keep in mind, that JSON **does not** read and populates static properties. So if you have some static properties, which should be serialized, mark them with `[JsonProperty]`.
4) Save the encrypted credential string/bson whereever you want and access them in the code via `<YourType>.Load(...)`. 
    - In the code 
    - In the web.config
    - in the app.config
    - as assembly resource
    - String Property of the Project (which will put it in the app/web config as well)
    - ...
5) Make sure your certificate will be accessible on the publish target the same way, you tested it.
6) Lean back and be calm, because it is much harder noe, to get to those precious credentials, if you keep in mind, that the private key must be kept as a secret. So put it somewhere **safe AND secure**.
7) Also keep in mind, that **Keeping a password as a managed string in memory is not a good idea!** So either throw away those Credentials as soon as you have finished their use or use `SecureStrings` wherever possible.
There is a `ToSecureString()` and `ToUnsecureString()` as an extension method in the Extensionlibrary as well.

#.public Methods
~~~csharp
    public class CryptoJson<T> where T : CryptoJson<T>
    {
        public CryptoJson();

        public static T Load(StoreLocation storeLocation, X509FindType x509FindType, object findValue, string encryptedData);
        public static T Load(X509Certificate2 certificate, string encryptedData);
        public static T Load(StoreLocation storeLocation, X509FindType x509FindType, object findValue, Stream encryptedData);
        public static T Load(X509Certificate2 certificate, Stream encryptedData);
        public string ToBase64(StoreLocation storeLocation, X509FindType x509FindType, object findValue);
        public string ToBase64(X509Certificate2 certificate);
        public MemoryStream ToBson(StoreLocation storeLocation, X509FindType x509FindType, object findValue);
        public MemoryStream ToBson(X509Certificate2 certificate);
    }
~~~
#.Load Credentials from Secure String
~~~csharp
    var userPassword1 = UserPasswordCredentials.Load(certificate, encryptedData); //or  
    var userPassword2 = UserPasswordCredentials.Load(StoreLocation.LocalMachine,X509FindType.FindByThumbprint, "thumbPrintOfCert", encryptedData);
~~~
