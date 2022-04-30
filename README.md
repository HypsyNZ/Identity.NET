# Identity.NET

[![Nuget](https://img.shields.io/nuget/v/Identity.NET)](https://www.nuget.org/packages/Identity.NET/)

Provides a Unique Identifier for the current PC and facility to Encrypt and Decrypt strings using that Identity


# Default Usage

Create an Identity for the local PC, The identity is only created once for the PC, Unless it is deleted.

```cs
UniqueIdentity.Initialize();
```

Encrypt a `string` using the local identity and no password
```cs
UniqueIdentity.Encrypt(string);
```

Decrypt a `string` using the local identity and no password
```cs
UniqueIdentity.Decrypt(string);
```

Get the local `UUID` as a `string`

```cs 
string identity = UniqueIdentity.UUID;
```



# Full Usage Options

| Argument  | Description   | Default |
| ------------ | ------------   | ---------- |
| pathToIdentity | Full Registry Path to store the `Identity` | `@"HKEY_LOCAL_MACHINE\SOFTWARE\Identity.NET"`
| password | An Additional password to secure the `Identity` | `Identity.NET`|
| useStrongIdentity | True if the identity is only valid if it is `Strong` | `true` (recommended)
| allowMixed | Whether `Mixed` keys should be allowed when the key is `Weak` | `true` (recommended)

```cs
UniqueIdentity.Initialize(pathToIdentity: @"HKEY_LOCAL_MACHINE\SOFTWARE\YourApp", 
                                password: "SomeSecurePassword", 
                       useStrongIdentity: true, 
                              allowMixed: true);
```
# Encrypt/Decrypt Strings

`strings` that are Encrypted/Decrypted are automatically protected by the `Identity` and an optional password

```cs
UniqueIdentity.Encrypt(string, "SomeDifferentSecurePassword");
UniqueIdentity.Decrypt(string, "SomeDifferentSecurePassword");
```

It is safe to use the `Default Identity` to `Encrypt/Decrypt` strings so long as you provide a password


# Password Protection

You can create a new `UniqueIdentity` for use with only your application and protect it with a different password

```cs
UniqueIdentity.Initialize(pathToIdentity: @"HKEY_LOCAL_MACHINE\SOFTWARE\YourApp", password: "SomeSecurePassword");
```

The password is not shared between the `UniqueIdentity` and `Encrypt/Decrypt`, You will need to remember both if you create a new `Identity`

Strings can only be `Encrypted/Decrypted` by the `Identity` that created them

# Strong / Mixed / Weak Identity

The `Strong` identity won't change if the user deletes the `Identity` manually, It will persist next time it gets created.

The `Mixed` identity is stronger than a `Weak` identity but has the same caveats

The `Weak` identity will change if the user deletes the `Identity` manually, for instance by reinstalling windows.

![https://i.imgur.com/60QUrlh.png](https://i.imgur.com/60QUrlh.png)

You can tell if you have a `Strong` or `Weak` identity because your `Identity` will match one of them

You have a `Mixed` identity if it doesn't match either of them

The `Strong` Identity may not be available on all PCs


# Checking ID

![https://i.imgur.com/lSKqtFm.png](https://i.imgur.com/lSKqtFm.png)

When you `Initialize()` the `Identity` it will return a bool that indicates if the `Identity` was created/loaded correctly, You can use this information in your application to `Exit` when a valid `Identity` can't be used.



# Safety

The data you `Encrypt/Decrypt` with the `Identity` is only as safe as the `Identity`, with some _effort_ it may be possible to get the `Identity` to run on another computer.

If you lose the `Identity` you will lose access to your data.

```cs
pathToIdentity: @"HKEY_LOCAL_MACHINE\SOFTWARE\YourApp"
```

You can manually `Export` the Identity from the `Registry` and store it on a `USB Stick`, But you will need to use `Password Protection` to get any benefit from this.
