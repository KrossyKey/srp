module Srp.Server

open Extensions
open System.Numerics
open Models
open Utils
/// **Description**
///   Server derived Session key
///   S = (Av^u) ^ b  
/// **Parameters**
///   * `param` - parameter of type `SRPParameter`
///   * `_A` - parameter of type `BigInteger`
///   * `_v` - parameter of type `BigInteger`
///   * `_u` - parameter of type `BigInteger`
///   * `_b` - parameter of type `BigInteger`
///
/// **Output Type**
///   * `Result<BigInteger,string>`
///
/// **Exceptions**
///
let S (param : SrpParameter) _A _v _u _b =

    match not (BigInteger.Zero >= _A || param.N <= _A) with
        | true ->   let ``(Av^u)`` = _A * BigInteger.ModPow(_v, _u, param.N)
                    BigInteger.ModPow(``(Av^u)``, _b, param.N) % param.N
                    |> bigIntPaddedToNBytes param.bits 
                    |> bytesToBigInt
                    |> Ok
        | false -> "Invalid server-supplied 'B', must be 1..N-1"
                |> Error

let checkM1 param _Client_M1_Hex _A _B _b _v = 
    let _u = Shared.u param _A _B
    let resS  = S param _A _v _u _b
    match resS with
    | Ok _S -> let _serverM1 = Shared.M1 param _A _B _S
               let rClientM1 = _Client_M1_Hex |> hexToBigInt
               match rClientM1 with
               | Ok _clientM1 when _clientM1 = _serverM1 -> _serverM1 |> Ok
               | Ok _ -> "Server M1 does not match client M1" |> Error
               | Error err -> err.Message |> Error
    | Error err  -> err |> Error

/// **Description**
///   * Checks if hex string for salt and verifier successfully parse to big integer
///   * Checks if byte range is within range of __param__
/// **Parameters**
///   * `param` - srp parameter `SrpParameter`
///   * `auth` - srp authentication model `AuthModel`
///
/// **Output Type**
///   * `Result<(BigInteger * BigInteger),string>`
///   * Identity * Verifier * Salt
///
/// **Exceptions**
///
let checkAccountCreation param auth = 

    let resVerifer = auth.verifierHex |> hexToBigInt 
    let resSalt = auth.saltHex |> hexToBigInt

    match (resVerifer, resSalt) with
    | (Ok _v, Ok _s) ->  let verifierByteNum = keyBytes param
                         let vCount = ((bigIntToBytes _v).Length)
                         match vCount with
                         | count when count = verifierByteNum -> let saltByteNum = keyBytes param
                                                                 let sCount = (bigIntToBytes _s).Length
                                                                 match sCount with
                                                                 | count when count = saltByteNum -> (auth.username,_v,_s) |> Ok
                                                                 | _ -> (sprintf "Salt bit count is not %i, instead %i" saltByteNum sCount) |> Error
                         | _ -> sprintf "Verifier bit count is not %i, instead is %i" verifierByteNum vCount |> Error        
    | (Error _v, Ok _) -> sprintf "Failed to parse verifier hex to number;%s" _v.Message |> Error
    | (Ok _, Error _s) -> sprintf "Failed to parse salt hex to number;%s" _s.Message |> Error
    | (Error _v, Error _s) -> sprintf "Failed to parse verifier and salt hex to number;%s;%s" _v.Message _s.Message |> Error



/// **Description**
///   * 
/// **Parameters**
///   * `param` - parameter of type `SrpParameter`
///   * `AHex` - hex of public client ephemeral value `string`
///
/// **Output Type**
///   * `Result<BigInteger,string>`
///
/// **Exceptions**
///
let checkA param _A_Hex = 

    let resA = _A_Hex |> hexToBigInt 
    match (resA) with
    | Ok A -> let bitCount = (bigIntToBytes A).Length
              let saltByteNum = (keyBytes param)
              match bitCount with
              | bCount when bCount = saltByteNum -> A |> Ok
              | _ -> sprintf "A bit count is not %i, instead %i" saltByteNum bitCount |> Error
    | Error err-> sprintf "Failed to parse A to number %s" err.Message |> Error 