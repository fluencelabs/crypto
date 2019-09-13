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

package fluence.crypto

import fluence.crypto.aes.{AesConfig, AesCrypt}
import org.scalactic.source.Position
import org.scalatest.{Assertion, Matchers, WordSpec}
import scodec.bits.ByteVector

import scala.util.{Random, Try}

class AesJSSpec extends WordSpec with Matchers with slogging.LazyLogging {

  def rndString(size: Int): String = Random.nextString(10)

  val conf = AesConfig()

  // TODO: use properties testing
  "aes crypto" should {
    "work with IV" in {
      val pass = ByteVector("pass".getBytes())
      val crypt = AesCrypt.build(pass, withIV = true, config = conf)

      val str = rndString(200).getBytes()
      val crypted = crypt.encrypt(str).right.get
      crypt.decrypt(crypted).right.get shouldBe str

      val fakeAes = AesCrypt.build(ByteVector("wrong".getBytes()), withIV = true, config = conf)
      checkCryptoError(fakeAes.decrypt(crypted), str)

      //we cannot check if first bytes is iv or already data, but encryption goes wrong
      val aesWithoutIV = AesCrypt.build(pass, withIV = false, config = conf)
      aesWithoutIV.decrypt(crypted).right.get shouldNot be(str)

      val aesWrongSalt = AesCrypt.build(pass, withIV = true, config = conf.copy(salt = rndString(10)))
      checkCryptoError(aesWrongSalt.decrypt(crypted), str)
    }

    "work without IV" in {
      val pass = ByteVector("pass".getBytes())
      val crypt = AesCrypt.build(pass, withIV = false, config = conf)

      val str = rndString(200).getBytes()
      val crypted = crypt.encrypt(str).right.get
      crypt.decrypt(crypted).right.get shouldBe str

      val fakeAes = AesCrypt.build(ByteVector("wrong".getBytes()), withIV = false, config = conf)
      checkCryptoError(fakeAes.decrypt(crypted), str)

      //we cannot check if first bytes is iv or already data, but encryption goes wrong
      val aesWithIV = AesCrypt.build(pass, withIV = true, config = conf)
      aesWithIV.decrypt(crypted).right.get shouldNot be(str)

      val aesWrongSalt = AesCrypt.build(pass, withIV = false, config = conf.copy(salt = rndString(10)))
      checkCryptoError(aesWrongSalt.decrypt(crypted), str)
    }

    /**
     * Checks if there is a crypto error or result is not equal with source result.
     */
    def checkCryptoError(tr: Crypto.Result[Array[Byte]], msg: Array[Byte])(implicit pos: Position): Assertion = {
      tr.map { r ⇒
        !(r sameElements msg)
      }.fold(
        _ ⇒ true,
        res => res
      ) shouldBe true
    }
  }
}
