/*
 * Copyright (C) 2017  Fluence Labs Limited
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package fluence.crypto.aes

import fluence.crypto.facade.cryptojs.{CryptOptions, CryptoJS, Key, KeyOptions}
import fluence.crypto.{Crypto, CryptoError}
import scodec.bits.ByteVector

import scala.language.higherKinds
import scala.scalajs.js.JSConverters._
import scala.scalajs.js.typedarray.Int8Array

class AesCrypt(password: Array[Char], withIV: Boolean, config: AesConfig) {

  private val salt = config.salt

  private val rndStr = CryptoJS.lib.WordArray

  //number of password hashing iterations
  private val iterationCount = config.iterationCount
  //initialisation vector must be the same length as block size
  private val IV_SIZE = 16
  private val BITS = 256
  //generate IV in hex
  private def generateIV = rndStr.random(IV_SIZE)

  private val pad = CryptoJS.pad.Pkcs7
  private val mode = CryptoJS.mode.CBC
  private val aes = CryptoJS.AES

  /**
   * Encrypt data.
   * data Data to encrypt
   * key Salted and hashed password
   * @return Encrypted data with IV
   */
  private val encryptData =
    Crypto.tryFn[(Array[Byte], Key), Array[Byte]] {
      case (data: Array[Byte], key: Key) ⇒
      //transform data to JS type
      val wordArray = CryptoJS.lib.WordArray.create(new Int8Array(data.toJSArray))
      val iv = if (withIV) Some(generateIV) else None
      val cryptOptions = CryptOptions(iv = iv, padding = pad, mode = mode)
      //encryption return base64 string, transform it to byte array
      val crypted = ByteVector.fromValidBase64(aes.encrypt(wordArray, key, cryptOptions).toString)
      //IV also needs to be transformed in byte array
      val byteIv = iv.map(i ⇒ ByteVector.fromValidHex(i.toString))
      byteIv.map(_.toArray ++ crypted.toArray).getOrElse(crypted.toArray)
    }("Cannot encrypt data")

  private val decryptData: Crypto.Func[(Key, String, Option[String]), ByteVector] =
    Crypto.tryFn[(Key, String, Option[String]), ByteVector] {
      case (key: Key, base64Data: String, iv: Option[String]) ⇒
      //parse IV to WordArray JS format
      val cryptOptions = CryptOptions(iv = iv.map(i ⇒ CryptoJS.enc.Hex.parse(i)), padding = pad, mode = mode)
      val dec = aes.decrypt(base64Data, key, cryptOptions)
      ByteVector.fromValidHex(dec.toString)
    }("Cannot decrypt data")

  /**
   * cipherText Encrypted data with IV
   * @return IV in hex and data in base64
   */
  private val detachData: Crypto.Func[Array[Byte], (Option[String], String)] =
    Crypto.tryFn {cipherText: Array[Byte] ⇒
      val dataWithParams = if (withIV) {
        val ivDec = ByteVector(cipherText.slice(0, IV_SIZE)).toHex
        val encMessage = cipherText.slice(IV_SIZE, cipherText.length)
        (Some(ivDec), encMessage)
      } else (None, cipherText)
      val (ivOp, data) = dataWithParams
      val base64 = ByteVector(data).toBase64
      (ivOp, base64)
    }("Cannot detach data and IV")

  /**
   * Hash password with salt `iterationCount` times
   */
  private val initSecretKey: Crypto.Func[Unit, Key] =
    Crypto.tryFn {_: Unit ⇒
      // get raw key from password and salt
      val keyOption = KeyOptions(BITS, iterations = iterationCount, hasher = CryptoJS.algo.SHA256)
      CryptoJS.PBKDF2(new String(password), salt, keyOption)
    }("Cannot init secret key")

  val decrypt: Crypto.Func[Array[Byte], Array[Byte]] =
    Crypto {
      input ⇒
        for {
          detachedData ← detachData(input)
          (iv, base64) = detachedData
          key ← initSecretKey(())
          decData ← decryptData((key, base64, iv))
          _ ← Crypto[Boolean, Unit](Either.cond(_, (), CryptoError("Cannot decrypt message with this password.")))(decData.nonEmpty )
        } yield decData.toArray
    }

  val encrypt: Crypto.Func[Array[Byte], Array[Byte]] =
    Crypto[Array[Byte], Array[Byte]] {
      input ⇒
        for {
          key ← initSecretKey( () )
          encrypted ← encryptData(input -> key)
        } yield encrypted
    }
}

object AesCrypt {

  def build(password: ByteVector, withIV: Boolean, config: AesConfig): Crypto.Cipher[Array[Byte]] = {
    val aes = new AesCrypt(password.toHex.toCharArray, withIV, config)
    Crypto.Cipher(aes.encrypt, aes.decrypt)
  }

}
