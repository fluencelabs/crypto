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
import org.scalatest.{Matchers, WordSpec}
import scodec.bits.ByteVector

import scala.util.Random

class JvmEcdsaSpec extends WordSpec with Matchers {

  def rndBytes(size: Int): Array[Byte] = Random.nextString(10).getBytes

  def rndByteVector(size: Int) = ByteVector(rndBytes(size))

  "jvm ecdsa algorithm" should {

    "restore key pair from secret key" in {
      val algo = Ecdsa.signAlgo
      val testKeys = algo.generateKeyPair(None).right.get

      val ecdsa = Ecdsa.ecdsa_secp256k1_sha256

      val newKeys = ecdsa.restorePairFromSecret(testKeys.secretKey).right.get

      testKeys shouldBe newKeys
    }
  }
}
