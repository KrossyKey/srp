module Srp.Extensions
    module Any = 
        let toString (any : 't) = 
            any.ToString()

    module Array = 
        let removeFirstIf (element : 't) (elements : 't[]) = 
            match Array.head elements with
            | e when e = element -> Array.tail elements
            | e -> elements

    module String = 
        open System.Text
        let toLower (sValue : string) =
            sValue.ToLower()
        let replace oldValue (replacement: string) (sValue : string) = 
            sValue.Replace(oldValue, replacement)
        let trimStart (trimmedChar : char) (sValue : string) =
            sValue.TrimStart(trimmedChar);
        let getBytesUTF8 (sValue : string) =
            sValue
            |> Encoding.UTF8.GetBytes
    module Regex = 
        open System.Text.RegularExpressions
        let replace pattern (replacement: string) (value : string) =
            Regex.Replace(value, pattern, replacement)

    module BigInteger = 
        open System.Globalization
        open System.Numerics
        open System
        
        let getBytes (bigInt : BigInteger) = 
            bigInt.ToByteArray()
        let modPow exp modulus value = 
            BigInteger.ModPow(value, exp, modulus)
        let parse (style:NumberStyles) value = 
            BigInteger.Parse(value, style)
        let multiply multiplyer value =
            BigInteger.Multiply(multiplyer, value)
       