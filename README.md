# Identity.NET

Provides a Unique Identifier for the current PC and facility to Encrypt and Decrypt strings using that Identity

# Usage

Create an Identity for the local PC

```cs
UniqueIdentity.Initialize(pathToIdentity: @"HKEY_LOCAL_MACHINE\SOFTWARE\YourApp", 
			  useStrongIdentity: true,
                          password: "SomeSecurePassword");
```

Encrypt a `string` using the local identity
```cs
UniqueIdentity.Encrypt(string);
```

Decrypt a `string` using the local identity
```cs
UniqueIdentity.Decrypt(string);
```

# Password Protection

The `UniqueIdentity` itself can be protected with a password, Which makes it more Unique, It will be encrypted/decrypted automatically

```cs
 UniqueIdentity.Initialize(password: "SomeSecurePassword");
```

`strings` can be password protected too

```cs
UniqueIdentity.Encrypt(string, "SomeDifferentSecurePassword");
UniqueIdentity.Decrypt(string, "SomeDifferentSecurePassword");
```

The password is not shared between `UniqueIdentity` and `Encrypt/Decrypt`

# Strong Vs Weak Identity

The `Strong` identity won't change if the user deletes the `Identity` manually, It will persist even if the user reinstalls `Windows`. The `Weak` identity will change if the user deletes the `Identity` manually, for instance by reinstalling windows.

The `Strong` Identity should always be available unless the user is trying to tamper or has an unusual configuration.