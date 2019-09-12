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

import cats.instances.either._
import fluence.crypto.{Crypto, JavaAlgorithm}
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.paddings.{PKCS7Padding, PaddedBufferedBlockCipher}
import org.bouncycastle.crypto.params.{KeyParameter, ParametersWithIV}
import org.bouncycastle.crypto.{CipherParameters, PBEParametersGenerator}
import scodec.bits.ByteVector

import scala.language.higherKinds
import scala.util.Random

case class DetachedData(ivData: Array[Byte], encData: Array[Byte])
case class DataWithParams(data: Array[Byte], params: CipherParameters)

/**
 * PBEWithSHA256And256BitAES-CBC-BC cryptography
 * PBE - Password-based encryption
 * SHA256 - hash for password
 * AES with CBC BC - Advanced Encryption Standard with Cipher Block Chaining
 * https://ru.wikipedia.org/wiki/Advanced_Encryption_Standard
 * https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_(CBC)
 * @param password User entered password
 * @param withIV Initialization vector to achieve semantic security, a property whereby repeated usage of the scheme
 *               under the same key does not allow an attacker to infer relationships between segments of the encrypted
 *               message
 */
class AesCrypt(password: Array[Char], withIV: Boolean, config: AesConfig) extends JavaAlgorithm {

  private val rnd = Random
  private val salt = config.salt.getBytes()

  //number of password hashing iterations
  private val iterationCount = config.iterationCount
  //initialisation vector must be the same length as block size
  private val IV_SIZE = 16
  private val BITS = 256
  private def generateIV: Array[Byte] = {
    val iv = new Array[Byte](IV_SIZE)
    rnd.nextBytes(iv)
    iv
  }






  /**
   * Key spec initialization
   */
  private val initSecretKey: Crypto.Func[(/*password*/Array[Char], /*salt*/Array[Byte]), Array[Byte]] =
    Crypto.tryFn[(Array[Char], Array[Byte]), Array[Byte]] {
      case (password, salt) ⇒
      PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password)
    }("Cannot init secret key")

  /**
   * Setup AES CBC cipher
   * encrypt: True for encryption and false for decryption
   *
   * @return cipher
   */
  private val setupAesCipher: Crypto.Func[(CipherParameters, Boolean), PaddedBufferedBlockCipher] =
    Crypto.tryFn[(CipherParameters, Boolean), PaddedBufferedBlockCipher] {
      case (params, encrypt) ⇒
      // setup AES cipher in CBC mode with PKCS7 padding
      val padding = new PKCS7Padding
      val cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine), padding)
      cipher.reset()
      cipher.init(encrypt, params)

      cipher
    }("Cannot setup aes cipher")

  private val cipherBytes: Crypto.Func[(Array[Byte], PaddedBufferedBlockCipher), Array[Byte]] =
    Crypto.tryFn[(Array[Byte], PaddedBufferedBlockCipher), Array[Byte]] {
      case (data, cipher) ⇒
      // create a temporary buffer to decode into (it'll include padding)
      val buf = new Array[Byte](cipher.getOutputSize(data.length))
      val outputLength = cipher.processBytes(data, 0, data.length, buf, 0)
      val lastBlockLength = cipher.doFinal(buf, outputLength)
      //remove padding
      buf.slice(0, outputLength + lastBlockLength)
    }("Error in cipher processing")

  /**
   *
   * dataWithParams Cata with cipher parameters
   * addData Additional data (nonce)
   * encrypt True for encryption and false for decryption
   * @return Crypted bytes
   */
  private val processData: Crypto.Func[(DataWithParams, Option[Array[Byte]], Boolean), Array[Byte]] =
    Crypto {
      case (dataWithParams, addData, encrypt) ⇒
      for {
        cipher ← setupAesCipher(dataWithParams.params -> encrypt)
        buf ← cipherBytes(dataWithParams.data, cipher)
      } yield addData.map(_ ++ buf).getOrElse(buf)
    }

  /**
   * encrypted data = initialization vector + data
   */
  private val detachIV: Crypto.Func[(Array[Byte], Int), DetachedData] =
    Crypto.tryFn[(Array[Byte], Int), DetachedData] {
      case (data, ivSize) ⇒
      val ivData = data.slice(0, ivSize)
      val encData = data.slice(ivSize, data.length)
      DetachedData(ivData, encData)
    }("Cannot detach data and IV")


  private val params: Crypto.Func[Array[Byte], KeyParameter] =
    Crypto.tryFn {
      key: Array[Byte] ⇒
      val pGen = new PKCS5S2ParametersGenerator(new SHA256Digest)
      pGen.init(key, salt, iterationCount)

      pGen.generateDerivedParameters(BITS).asInstanceOf[KeyParameter]
    }("Cannot generate key parameters")

  private val paramsWithIV: Crypto.Func[(Array[Byte], Array[Byte]), ParametersWithIV] =
    Crypto{
      case (key: Array[Byte], iv: Array[Byte]) ⇒
        params
          .andThen(Crypto.tryFn((kp: KeyParameter) ⇒ new ParametersWithIV(kp, iv))("Cannot generate key parameters with IV"))
          .run(key)
    }

  /**
   * Generate key parameters with IV if it is necessary
   * key Password
   * @return Optional IV and cipher parameters
   */
  val extDataWithParams: Crypto.Func[Array[Byte],(Option[Array[Byte]], CipherParameters)] =
    Crypto(key ⇒
      if (withIV) {
        val ivData = generateIV

        // setup cipher parameters with key and IV
        paramsWithIV(key, ivData).map(k ⇒ (Some(ivData), k))
      } else {
        params(key).map(k ⇒ (None, k))
      }
    )

  private val detachDataAndGetParams: Crypto.Func[(Array[Byte], Array[Char], Array[Byte], Boolean), DataWithParams] =
  Crypto{
    case (data, password, salt, withIV) ⇒
    if (withIV) {
      for {
        ivDataWithEncData ← detachIV(data -> IV_SIZE)
        key ← initSecretKey(password -> salt)
        // setup cipher parameters with key and IV
        paramsWithIV ← paramsWithIV(key, ivDataWithEncData.ivData)
      } yield DataWithParams(ivDataWithEncData.encData, paramsWithIV)
    } else {
      for {
        key ← initSecretKey(password -> salt)
        // setup cipher parameters with key
        params ← params(key)
      } yield DataWithParams(data, params)
    }
  }

  val decrypt: Crypto.Func[Array[Byte], Array[Byte]] =
    Crypto[Array[Byte], Array[Byte]] {
      input: Array[Byte] ⇒
        for {
          dataWithParams ← detachDataAndGetParams((input, password, salt, withIV))
          decData ← processData( (dataWithParams, None, /*encrypt =*/ false))
        } yield decData
    }

  val encrypt: Crypto.Func[Array[Byte], Array[Byte]] =
    Crypto {
      input: Array[Byte] ⇒
        for {
          key ← initSecretKey(password -> salt)
          extDataWithParams ← extDataWithParams(key)
          encData ← processData((DataWithParams(input, extDataWithParams._2), extDataWithParams._1, /*encrypt =*/ true))
        } yield encData

    }
}

object AesCrypt {

  def build(password: ByteVector, withIV: Boolean, config: AesConfig): Crypto.Cipher[Array[Byte]] = {
    val aes = new AesCrypt(password.toHex.toCharArray, withIV, config)
    Crypto.Cipher(aes.encrypt, aes.decrypt)
  }

}
