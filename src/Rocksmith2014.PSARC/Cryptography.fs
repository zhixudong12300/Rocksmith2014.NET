module Rocksmith2014.PSARC.Cryptography

open System
open System.IO
open System.Security.Cryptography
open System.Text

let private psarcKey =
    "\xC5\x3D\xB2\x38\x70\xA1\xA2\xF7\x1C\xAE\x64\x06\x1F\xDD\x0E\x11\x57\x30\x9D\xC8\x52\x04\xD4\xC5\xBF\xDF\x25\x09\x0D\xF2\x57\x2C"B

let private getDecryptStream (input: Stream) =
    use aes = new AesManaged(Mode = CipherMode.CFB,
                             Padding = PaddingMode.None,
                             BlockSize = 128,
                             FeedbackSize = 128)

    let decryptor = aes.CreateDecryptor(psarcKey, Array.zeroCreate<byte> 16)
    new CryptoStream(input, decryptor, CryptoStreamMode.Read, true)

let private getEncryptStream (output: Stream) =
    use aes = new AesManaged(Mode = CipherMode.CFB,
                             Padding = PaddingMode.Zeros,
                             BlockSize = 128,
                             FeedbackSize = 128)

    let encryptor = aes.CreateEncryptor(psarcKey, Array.zeroCreate<byte> 16)
    new CryptoStream(output, encryptor, CryptoStreamMode.Write, true)

/// Decrypts a PSARC header from the input stream into the output stream.
let decrypt (input: Stream) (output: Stream) (length: int32) =
    let buffer = Array.zeroCreate<byte> length
    use decStream = getDecryptStream input
    ignore <| decStream.Read(buffer, 0, length)

    output.Write(buffer, 0, length)
    output.Flush()
    output.Position <- 0L

/// Encrypts a plain PSARC header from the input stream into the output stream.
let encrypt (input: Stream) (output: Stream)  =
    using (getEncryptStream output) input.CopyTo

/// Calculates an MD5 hash for the given string.
let md5Hash (name: string) =
    if String.IsNullOrEmpty name then Array.zeroCreate<byte> 16
    else using (new MD5CryptoServiceProvider()) (fun md5 -> md5.ComputeHash(Encoding.ASCII.GetBytes(name)))
