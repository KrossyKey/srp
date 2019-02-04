module Srp.Utils

open System.Security.Cryptography
open System.Numerics
open System.Globalization
open Extensions




//Hash Algorithm type
type HashAlg =
    | SHA1
    | SHA256

 
/// **Description**
///   * Reverses the order of the array, converts to 
///   * Big integer, and if negative, applys bit shift 
///   operation
/// **Parameters**
///   * `bytes` - parameter of type `byte []`
///
/// **Output Type**
///   * `BigInteger`
///
/// **Exceptions**
///
let bytesToBigInt (bytes : byte[]) = 
    Array.rev bytes
    |> BigInteger
    |> function
        | bigInt when bigInt < BigInteger.Zero -> (BigInteger.One <<< (bytes.Length * 8)) + bigInt;
        | bigInt -> bigInt


/// **Description**
///   * Converts big integer to bytes, reverses order
///   * And trims beggining if it is 0
/// **Parameters**
///   * `bigInt` - parameter of type `BigInteger`
///
/// **Output Type**
///   * `byte []`
///
/// **Exceptions**
///
let bigIntToBytes (bigInt : BigInteger) =
    bigInt
    |> BigInteger.getBytes
    |> Array.rev
    |> Array.removeFirstIf 0uy


/// **Description**
///   * Removes whitespace from hex string and 
///   * Tries to parse to big integer. 
///   * If unsuccessful it returns a zero big integer
/// **Parameters**
///   * `hex` - parameter of type `string`
///
/// **Output Type**
///   * `Result<BigInteger,string>`
///
/// **Exceptions**
///
let hexToBigInt (hex : string) =
    try
        ("0" + hex 
            |> Regex.replace @"\s" System.String.Empty
            |> BigInteger.parse NumberStyles.HexNumber)
            |> Ok
    with error -> 
            error |> Error


/// **Description**
///   * Iterates through all bytes and converts 
///   * to hexadecimal character and concatenates 
///   * to string
/// **Parameters**
///   * `bytes` - parameter of type `byte []`
///
/// **Output Type**
///   * `string`
///
/// **Exceptions**
///
let bytesToHex bytes = 
    bytes 
    |> Array.map (fun (b : byte) -> sprintf "%x" b)
    |> String.concat System.String.Empty



/// **Description**
///   * Gets bytes from big integer and converts it to hexadecimal string
/// **Parameters**
///   * `value` - parameter of type `bigint`
///
/// **Output Type**
///   * `string`
///
/// **Exceptions**
///
let bigIntToHex (value : bigint) =
    value
        |> BigInteger.getBytes
        |> bytesToHex



/// **Description**
///   * Calculates difference between byte array and required length
///   * Appends that amount in a form of a zero array to beggining of
///   byte array
/// **Parameters**
///   * `bytes` - parameter of type `byte []`
///   * `length` - parameter of type `int`
///
/// **Output Type**
///   * `byte []`
///
/// **Exceptions**
///
let padTo (bytes:byte[]) length = 
    let paddingLen = match (length - bytes.Length) with
                     | p when p >= 0 -> p
                     | _ -> 0
    Array.append (Array.zeroCreate(paddingLen)) bytes


/// **Description**
///   * Pads byte array to the amount of bytes of srp parameter
/// **Parameters**
///   * `constant` - parameter of type `SRPParameter`
///   * `bytes` - parameter of type `byte []`
///
/// **Output Type**
///   * `byte []`
///
/// **Exceptions**
///
let padToN bits bytes = 
    padTo bytes (bits/8)

let bigIntPaddedToNBytes bits bigInt = 
    bigInt
    |> bigIntToBytes
    |> padToN bits



/// **Description**
///   * Chooses hash algorithm based on __hashAlg__
/// **Parameters**
///   * `hashAlg` - parameter of type `HashAlg`
///
/// **Output Type**
///   * `HashAlgorithm`
///
/// **Exceptions**
///
let hashAlgorithm hashAlg : HashAlgorithm =
    match hashAlg with
    | SHA1 -> SHA1.Create() :> HashAlgorithm
    | SHA256 -> SHA256.Create() :> HashAlgorithm



/// **Description**
///   * Computes hash of byte array with given 
///   * hashing algorithm
/// **Parameters**
///   * `hashAlg` - parameter of type `HashAlg`
///   * `bytes` - parameter of type `byte []`
///
/// **Output Type**
///   * `byte []`
///
/// **Exceptions**
///
let bytesToHash hashAlg (bytes:byte[]) =
    bytes
        |> (hashAlg |> hashAlgorithm).ComputeHash

/// **Description**
///   * Generates random buffer using __RNGCryptoServiceProvider__
/// **Parameters**
///   * `arraySize` - parameter of type `int`
///
/// **Output Type**
///   * `byte []`
///
/// **Exceptions**
///
let generateRandom arraySize =
    let generator = new RNGCryptoServiceProvider()
    let buffer = Array.zeroCreate arraySize
    generator.GetBytes buffer
    buffer