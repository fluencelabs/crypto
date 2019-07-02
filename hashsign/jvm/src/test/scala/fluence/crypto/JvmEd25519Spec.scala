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
import fluence.crypto.eddsa.Ed25519
import fluence.crypto.keystore.FileKeyStorage
import org.scalatest.{Matchers, WordSpec}
import scodec.bits.ByteVector

import scala.util.{Random, Try}

class JvmEd25519Spec extends WordSpec with Matchers {

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
    "store and read key from file" in {
      val algo = Ed25519.signAlgo
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
  }
}
