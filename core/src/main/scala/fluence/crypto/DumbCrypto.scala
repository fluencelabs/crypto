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

import java.security.SecureRandom

import cats.data.Kleisli
import fluence.crypto.signature.{SignAlgo, Signature, SignatureChecker, Signer}
import cats.syntax.either._
import scodec.bits.ByteVector

import scala.language.higherKinds

object DumbCrypto {

  lazy val signAlgo: SignAlgo =
    SignAlgo(
      "dumb",
      Kleisli[Crypto.Err, Option[Array[Byte]], KeyPair] { seedOpt ⇒
        val seed = seedOpt.getOrElse {
          new SecureRandom().generateSeed(32)
        }
        KeyPair.fromBytes(seed, seed).asRight
      },
      keyPair ⇒ Signer(keyPair.publicKey, Kleisli[Crypto.Err, ByteVector, Signature](plain ⇒ Signature(plain.reverse).asRight)),
      publicKey ⇒
        SignatureChecker(
          Kleisli{
            case (sgn, msg) ⇒ Either.cond(sgn.sign == msg.reverse, (), CryptoError("Signatures mismatch"))
          }
  )
    )

  lazy val cipherString: Crypto.Cipher[String] =
    Crypto.Cipher(
      Kleisli[Crypto.Err, String, Array[Byte]](_.getBytes.asRight[CryptoError]),
      Kleisli[Crypto.Err, Array[Byte], String](bytes ⇒ new String(bytes).asRight[CryptoError])
    )

  lazy val noOpHasher: Crypto.Hasher[Array[Byte], Array[Byte]] =
    Kleisli[Crypto.Err, Array[Byte], Array[Byte]](_.asRight)

  lazy val testHasher: Crypto.Hasher[Array[Byte], Array[Byte]] =
    Kleisli[Crypto.Err, Array[Byte], Array[Byte]](bytes ⇒ ("H<" + new String(bytes) + ">").getBytes().asRight)
}
