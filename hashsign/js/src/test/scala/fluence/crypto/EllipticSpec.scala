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

import cats.data.EitherT
import cats.instances.try_._
import fluence.crypto.ecdsa.Ecdsa
import fluence.crypto.facade.ed25519.Supercop
import fluence.crypto.signature.Signature
import io.scalajs.nodejs.buffer.Buffer
import org.scalatest.{Matchers, WordSpec}
import scodec.bits.ByteVector

import scala.util.{Random, Try}

class EllipticSpec extends WordSpec with Matchers {

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

  "ecdsa algorithm" should {
    "correct sign and verify data" in {
      val algorithm = Ecdsa.ecdsa_secp256k1_sha256

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
      val algo = Ecdsa.ecdsaSignAlgo
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
      val algo = Ecdsa.ecdsaSignAlgo
      val keys = algo.generateKeyPair.unsafe(None)
      val signer = algo.signer(keys)
      val checker = algo.checker(keys.publicKey)
      val data = rndByteVector(10)

      val sign = signer.sign(data).extract

      the[CryptoError] thrownBy checker.check(Signature(rndByteVector(10)), data).value.flatMap(_.toTry).get
      val invalidChecker = algo.checker(KeyPair.fromByteVectors(rndByteVector(10), rndByteVector(10)).publicKey)
      the[CryptoError] thrownBy invalidChecker
        .check(sign, data)
        .value
        .flatMap(_.toTry)
        .get
    }
  }

  "ed25519 algorithm" should {

    "all correct" in {
      val privateKey = ByteVector.fromValidHex("c55c4ef0620e59f5686555f61827e29011d50238af927245e6c64aa74fdc01fb")

      val msg = ByteVector.fromValidHex("eab696e7a5bde4a880e68789e38caae691be7ae9909ae39c84e98ca1")
      val pb = KeyPair.Public(ByteVector.fromValidHex("2acfc5104d6439cdbbdf42561580bd06a297ad74e2a26eaf7ca25ac80222267a"))
      println("PB = " + pb.value.toArray.mkString(" "))
      println("PB = " + pb.value.toArray.length)


      val sig = Signature(ByteVector.fromValidHex("018a8e5dbe7fc7ce23f16e9ac1e9b307ce1b05b21b45d4cf34df47ade64d797d48282a83b2cfb03409f7a97f5e062b5c11d5146272328b566dfae3ee4b37580c"))


      val bufPrivate = Buffer.from(privateKey.toHex, "hex")
      val bufMsg = Buffer.from(msg.toHex, "hex")
      val bufPublic = Buffer.from(pb.value.toHex, "hex")
      val res2 = Supercop.verify(Buffer.from(sig.sign.toHex, "hex"), bufMsg, bufPublic)
      println("RES === " + res2)

      val sign = Supercop.sign(bufMsg, bufPublic, bufPrivate)
      println("GENERATED SIGN === " + sign.toString("hex"))

      val kp = Supercop.createKeyPair(Buffer.from(ByteVector(Array[Byte](1,2,3)).toHex, "hex"))
      println("keypair = " + kp.publicKey.toString("hex"))
      println("keypair = " + kp.secretKey.toString("hex"))


    }

    /*"correct sign and verify data" in {
      val algorithm = Elliptic.ed25519

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
      val algo = Elliptic.ed25519SignAlgo
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
      val algo = Elliptic.ed25519SignAlgo
      val keys = algo.generateKeyPair.unsafe(None)
      val signer = algo.signer(keys)
      val checker = algo.checker(keys.publicKey)
      val data = rndByteVector(10)

      val sign = signer.sign(data).extract

      the[CryptoError] thrownBy checker.check(Signature(rndByteVector(10)), data).value.flatMap(_.toTry).get
      val invalidChecker = algo.checker(KeyPair.fromByteVectors(rndByteVector(10), rndByteVector(10)).publicKey)
      the[CryptoError] thrownBy invalidChecker
        .check(sign, data)
        .value
        .flatMap(_.toTry)
        .get
    }*/
  }
}
