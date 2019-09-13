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

import fluence.crypto.ecdsa.Ecdsa
import fluence.crypto.signature.{SignAlgo, Signature}
import org.scalatest.{Matchers, WordSpec}
import scodec.bits.ByteVector

import scala.util.{Random, Try}

class EcdsaSpec extends WordSpec with Matchers {

  def rndBytes(size: Int): Array[Byte] = Random.nextString(10).getBytes

  def rndByteVector(size: Int) = ByteVector(rndBytes(size))

  "ecdsa algorithm" should {
    "correct sign and verify data" in {
      val algorithm: SignAlgo = Ecdsa.signAlgo

      val keys = algorithm.generateKeyPair(None).right.get
      val pubKey = keys.publicKey
      val data = rndByteVector(10)
      val sign = algorithm.signer(keys).sign(data).right.get

      algorithm.checker(pubKey).check((sign, data)).isRight shouldBe true

      val randomData = rndByteVector(10)
      val randomSign = algorithm.signer(keys).sign(randomData).right.get

      algorithm.checker(pubKey).check(randomSign -> data).isRight shouldBe false

      algorithm.checker(pubKey).check(sign -> randomData).isRight shouldBe false
    }

    "correctly work with signer and checker" in {
      val algo: SignAlgo = Ecdsa.signAlgo
      val keys = algo.generateKeyPair(None).right.get
      val signer = algo.signer(keys)
      val checker = algo.checker(keys.publicKey)

      val data = rndByteVector(10)
      val sign = signer.sign(data).right.get

      checker.check(sign -> data).isRight shouldBe true

      val randomSign = signer.sign(rndByteVector(10)).right.get
      checker.check(randomSign -> data).isRight shouldBe false
    }

    "throw an errors on invalid data" in {
      val algo: SignAlgo = Ecdsa.signAlgo
      val keys = algo.generateKeyPair(None).right.get
      val signer = algo.signer(keys)
      val checker = algo.checker(keys.publicKey)
      val data = rndByteVector(10)

      val sign = signer.sign(data).right.get

      the[CryptoError] thrownBy {
        checker.check(Signature(rndByteVector(10)) -> data).toTry.get
      }
      val invalidChecker = algo.checker(KeyPair.fromByteVectors(rndByteVector(10), rndByteVector(10)).publicKey)
      the[CryptoError] thrownBy {
        invalidChecker
          .check(sign -> data)
          .toTry
          .get
      }
    }
  }
}
