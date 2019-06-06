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

import java.io.File

import cats.data.EitherT
import cats.instances.try_._
import fluence.crypto.ecdsa.Ed25519
import fluence.crypto.keystore.FileKeyStorage
import fluence.crypto.signature.Signature
import org.scalatest.{Matchers, WordSpec}
import scodec.bits.ByteVector

import scala.util.{Random, Try}

class Ed25519Spec extends WordSpec with Matchers {

  def rndBytes(size: Int): Array[Byte] = Random.nextString(10).getBytes

  def rndByteVector(size: Int) = ByteVector(rndBytes(size))

  private implicit class TryEitherTExtractor[A <: Throwable, B](et: EitherT[Try, A, B]) {

    def extract: B =
      et.value.map {
        case Left(e) ⇒ fail(e) // for making test fail message more describable
        case Right(v) ⇒ v
      }.get

    def isOk: Boolean = et.value.fold(_ ⇒ false, _.isRight)
  }

  "ed25519 algorithm" should {
    "correct sign and verify data" in {
      val algorithm = Ed25519.ed25519(32)

      val keys = algorithm.generateKeyPair.unsafe(None)
      val pubKey = keys.publicKey
      val data = rndByteVector(10)
      val sign = algorithm.sign[Try](keys, data).extract

      algorithm.verify[Try](pubKey, sign, data).isOk shouldBe true

      val randomData = rndByteVector(10)
      val randomSign = algorithm.sign(keys, randomData).extract

      algorithm.verify(pubKey, randomSign, data).isOk shouldBe false

      algorithm.verify(pubKey, sign, randomData).isOk shouldBe false
    }

    "correctly work with signer and checker" in {
      val algo = Ed25519.signAlgo(32)
      val keys = algo.generateKeyPair.unsafe(None)
      val signer = algo.signer(keys)
      val checker = algo.checker(keys.publicKey)

      val data = rndByteVector(10)
      val sign = signer.sign(data).extract

      checker.check(sign, data).isOk shouldBe true

      val randomSign = signer.sign(rndByteVector(10)).extract
      checker.check(randomSign, data).isOk shouldBe false
    }

    "throw an errors on invalid data" in {
      val algo = Ed25519.signAlgo(32)
      val keys = algo.generateKeyPair.unsafe(None)
      val signer = algo.signer(keys)
      val checker = algo.checker(keys.publicKey)
      val data = rndByteVector(10)

      val sign = signer.sign(data).extract

      the[CryptoError] thrownBy {
        checker.check(Signature(rndByteVector(10)), data).value.flatMap(_.toTry).get
      }
      val invalidChecker = algo.checker(KeyPair.fromByteVectors(rndByteVector(10), rndByteVector(10)).publicKey)
      the[CryptoError] thrownBy {
        invalidChecker
          .check(sign, data)
          .value
          .flatMap(_.toTry)
          .get
      }
    }

    "store and read key from file" in {
      val algo = Ed25519.signAlgo(32)
      val keys = algo.generateKeyPair.unsafe(None)

      val keyFile = File.createTempFile("test", "")
      if (keyFile.exists()) keyFile.delete()
      val storage = new FileKeyStorage(keyFile)

      storage.storeKeyPair(keys).unsafeRunSync()

      val keysReadE = storage.readKeyPair
      val keysRead = keysReadE.unsafeRunSync()

      val signer = algo.signer(keys)
      val data = rndByteVector(10)
      val sign = signer.sign(data).extract

      algo.checker(keys.publicKey).check(sign, data).isOk shouldBe true
      algo.checker(keysRead.publicKey).check(sign, data).isOk shouldBe true

      //try to store key into previously created file
      storage.storeKeyPair(keys).attempt.unsafeRunSync().isLeft shouldBe true
    }

    "restore key pair from secret key" in {
      val algo = Ed25519.signAlgo(32)
      val testKeys = algo.generateKeyPair.unsafe(None)

      val ed25519 = Ed25519.ed25519(32)

      val newKeys = ed25519.restorePairFromSecret(testKeys.secretKey).extract

      testKeys shouldBe newKeys
    }

    "ecdsa is work fine with tendermint keys" in {
      /*
        {
          "address": "C08269A8AACD53C3488F16F285821DAC77CF5DEF",
          "pub_key": {
            "type": "tendermint/PubKeyEd25519",
            "value": "FWB5lXZ/TT2132+jXp/8aQzNwISwp9uuFz4z0TXDdxY="
          },
          "priv_key": {
            "type": "tendermint/PrivKeyEd25519",
            "value": "P6jw9q/Rytdxpv5Wxs1aYA8w82uS0x3CpmS9+GpaMGIVYHmVdn9NPbXfb6Nen/xpDM3AhLCn264XPjPRNcN3Fg=="
          }
        }
       */

      val privKeyBase64 = "P6jw9q/Rytdxpv5Wxs1aYA8w82uS0x3CpmS9+GpaMGIVYHmVdn9NPbXfb6Nen/xpDM3AhLCn264XPjPRNcN3Fg=="
      val pubKeyBase64 = "FWB5lXZ/TT2132+jXp/8aQzNwISwp9uuFz4z0TXDdxY="

      val privKey = ByteVector.fromBase64Descriptive(privKeyBase64).right.get
      val pubKey = ByteVector.fromBase64Descriptive(pubKeyBase64).right.get

      val restored = Ed25519.tendermintEd25519
        .restorePairFromSecret[Try](KeyPair.Secret(privKey.dropRight(32)))
        .value
        .get
        .right
        .get
        .publicKey
        .bytes

      restored shouldBe pubKey.toArray
      restored shouldBe privKey.drop(32).toArray
    }
  }
}
