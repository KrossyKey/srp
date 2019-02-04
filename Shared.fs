module Srp.Shared

open Models
open Extensions
open Utils
open System.Numerics
open System


type HArg = 
| BInt of BigInteger
| Buff of byte[] 

/// **Description**
///   One way hash function
///   * Appends bytes array into one array
///   * Hashes resulting bytes array
/// **Parameters**
///   * `param` - hash algorithm `SRPParameter`
///   * `args` -  arguements to concat and hash `HArg list`
///
/// **Output Type**
///   * `BigInteger`
///
/// **Exceptions**
///
let H (param : SrpParameter) (args : HArg list) =
    args
        |> List.map (fun hArg -> match hArg with
                                  | BInt bigInt -> bigInt |> bigIntToBytes
                                  | Buff bytes ->  bytes)
        |> List.reduce Array.append 
        |> bytesToHash param.hashAlg
        |> bytesToBigInt


/// **Description**
///   Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6).
///   * Pad __N__ and __g__ with zeros to the byte size of N
///   * Concatenate the two and apple one-way hash function __H__
///   * Converts byte array to big integer
/// **Parameters**
///   * `param` -  srp parameter `SRPParameter`
///
/// **Output Type**
///   * `BigInteger`
///
/// **Exceptions**
///
let k param =
    (param ,[Buff (param.N |> bigIntPaddedToNBytes param.bits); 
             Buff (param.g |> bigIntPaddedToNBytes param.bits)]) 
    ||> H 


/// **Description**
///   Private Key
///   x = H(salt || H(username || ":" || password))
///   * Combine identity (username) and password and convert to UTF8 bytes
///   * Hash byte array with __param__'s hash algorithm
///   * Combines salt buffer and identity-password hashed buffer to array
///   * Applys resulting array to one-way hash function __H__
///   
/// **Parameters**
///   * `param` - srp hash algorithm `SRPParameter`
///   * `_s` - salt `byte []`
///   * `_I` - user identity `string`
///   * `_p` - user password `string`
///
/// **Output Type**
///   * `BigInteger`
///
/// **Exceptions**
///
let x param _s (_I : string) (_p : string)= 
    let ipBytes = (sprintf "%s:%s" _I _p)
                |> String.getBytesUTF8
                |> bytesToHash param.hashAlg
    (param, [Buff _s; Buff ipBytes ]) 
                ||> H 



/// **Description**
///   Computes Verifier
///   v = g^x % N
///   * Mods g (modulous) by private key (__x__) and takes it to exponential of N
///  
/// **Parameters**
///   * `param` - srp parameter `SRPParameter`
///   * `_g` - srp N modulo `BigInteger`
///   * `_x` - user computed private key `BigInteger`
///
/// **Output Type**
///   * `BigInteger`
///
/// **Exceptions**
///
let v param _x =
    param.g |> BigInteger.modPow _x param.N



/// **Description**
///   Client Public ephemeral value
///   A = g^a % N
///   * Mods g (modulous) by private key (__a__) and takes it to exponential of N
///
/// **Parameters**
///   * `param` - srp parameter `SRPParameter`
///   * `_a` -  client secret generated ephemeral value `BigInteger`
///
/// **Output Type**
///   * `BigInteger`
///
/// **Exceptions**
let A param (_a : BigInteger) =
    let aBitLength = float((_a |> bigIntToBytes).Length) * 8.0
    if (Math.Ceiling( aBitLength) < 256.0)
    then printfn "A: client key length %f is less than the recommended 256" aBitLength
    param.g |> BigInteger.modPow _a param.N
    |> bigIntPaddedToNBytes param.bits 
    |> bytesToBigInt

/// **Description**
///   B = kv + g^b
///   Server Public ephemeral value
/// **Parameters**
///   * `param` - srp parameter `SRPParameter`
///   * `_k` - srp multiplier `BigInteger`
///   * `_b` - server secret generated ephemeral value `BigInteger`
///   * `_v` - server stored verifier `BigInteger`
///
/// **Output Type**
///   * `BigInteger`
///
/// **Exceptions**
///
let B param _k _b _v  =
    (_k * _v + BigInteger.ModPow(param.g, _b, param.N)) % param.N
    |> bigIntPaddedToNBytes param.bits 
    |> bytesToBigInt

/// **Description**
///   Random scrambling parameter
///   u = SHA-1(A || B)
///   * Convert ___A__ and ___B__ big integers to byte array
///   * Concatenate byte arrays and send to one way hash __H__
///   * Convert byte array to big integer
/// **Parameters**
///   * `hashAlg` - srp hash algorithm `HashAlg`
///   * `_A` - client puplic ephemeral value `bigint`
///   * `_B` - server puplic ephemeral value `bigint`
///
/// **Output Type**
///   * `BigInteger`
///
/// **Exceptions**
///
let u hashAlg _A _B  =
    (hashAlg, [BInt _A; BInt _B])
    ||> H

/// **Description**
///   Proof variable
///   K = H(S)
/// **Parameters**
///   * `param` - srp parameter `SRPParameter`
///   * `_S` - session key `bigint`
///
/// **Output Type**
///   * `BigInteger`
///
/// **Exceptions**
///
let K param (_S : BigInteger) =
    H param [(BInt _S)]



/// **Description**
///   M1 challenge is used in place of the password as proof of identity (K)
///   * Take the one way hash of the client and sever ephemeral values
///   and the session key
/// **Parameters**
///   * `param` - srp parameters `SRPParameter`
///   * `_A` - client puplic ephemeral value `bigint`
///   * `_B` - server puplic ephemeral value `bigint`
///   * `_S_buf` - session key `bigint`
///
/// **Output Type**
///   * `BigInteger`
///
/// **Exceptions**
///
let M1 param _A _B _S = 
    H param [BInt _A; BInt _B ; BInt _S ]


/// **Description**
///   M2 challenge is used to prove authenticity of server
/// **Parameters**
///   * `param` - srp parameter `SRPParameter`
///   * `_A` - client puplic ephemeral value `BigInteger`
///   * `_M1` - used to prove idetity `BigInteger`
///   * `_K` - shared hashed session key `BigInteger`
///
/// **Output Type**
///   * `BigInteger`
///
/// **Exceptions**
///
let M2 param _A _M1 _K = 
    H param [BInt _A;BInt _M1; BInt _K]



