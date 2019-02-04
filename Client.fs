
module Srp.Client

open System.Numerics
open Utils
open Srp.Shared
open Models
open Extensions

/// **Description**
///  /// S = (B - kg^x) ^ (a + ux) (mod N)
///   Client Session  Key
/// **Parameters**
///   * `param` - parameter of type `SRPParameter`
///   * `_B` - parameter of type `BigInteger`
///   * `_x` - parameter of type `BigInteger`
///   * `_u` - parameter of type `BigInteger`
///   * `_a` - parameter of type `BigInteger`
///
/// **Output Type**
///   * `BigInteger`
///
/// **Exceptions**
///
let S (param : SrpParameter) _B _x _u _a =
    match not (BigInteger.Zero >= _B || param.N <= _B) with
    | true ->   let _k = k param
                let gPowX = param.g |> BigInteger.modPow _x param.N
                let ``(B - kg^x)`` = (_B - (_k * gPowX))
                let ``(a + ux)`` = _x * _u + _a
                BigInteger.ModPow(``(B - kg^x)``, ``(a + ux)``, param.N) % param.N
                |> bigIntPaddedToNBytes param.bits 
                |> bytesToBigInt
                |> Ok
    | false -> "invalid server-supplied 'B', must be 1..N-1"
                |> Error


/// **Description**
///   * Checks if Server and Client M2 derivations are the same
///   * If not then return Error that server is not authentic
/// **Parameters**
///   * `serverM2` - srp server M2 `BigInteger`
///   * `clientM2` - srp server M2 `BigInteger`
///
/// **Output Type**
///   * `Result<'a,string>`
///
/// **Exceptions**
///
let checkM2 (serverM2 : BigInteger) (clientM2 : BigInteger) = 
    match (clientM2 = serverM2) with
    | true -> serverM2 |> Ok
    | false -> "server is not authentic" |> Error
    

/// **Description**
///
/// **Parameters**
///   * `param` - srp parameter `SRPParameter`
///   * `I` - srp identity `string`
///   * `p` - srp password `string`
///
/// **Output Type**
///   * `string * byte [] * BigInteger`
///
/// **Exceptions**
///
let createAccount param _I _p =
    let _s = generateRandom (keyBytes param)
    let _x = x param _s _I _p
    let _v = v param _x
    (_I, _s, _v )

