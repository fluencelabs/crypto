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

package fluence.crypto.eddsa

import cats.Monad
import cats.data.EitherT
import fluence.crypto.CryptoError.nonFatalHandling
import fluence.crypto.facade.ed25519.Supercop
import fluence.crypto.hash.JsCryptoHasher
import fluence.crypto.{Crypto, CryptoError, KeyPair, CryptoJsHelpers}
import fluence.crypto.signature.{SignAlgo, Signature, SignatureChecker, Signer}
import io.scalajs.nodejs.buffer.Buffer
import scodec.bits.ByteVector

import scala.language.higherKinds

class Ed25519(hasher: Option[Crypto.Hasher[Array[Byte], Array[Byte]]]) {

  import CryptoJsHelpers._

  def sign[F[_]: Monad](keyPair: KeyPair, message: ByteVector): EitherT[F, CryptoError, Signature] =
    for {
      hash ← JsCryptoHasher.hash(message, hasher)
      sign ← nonFatalHandling {
        Supercop.sign(
          Buffer.from(ByteVector(hash).toHex, "hex"),
          keyPair.publicKey.value.toJsBuffer,
          keyPair.secretKey.value.toJsBuffer
        )
      }("Error on signing message by js/ed25519 signature")
    } yield Signature(ByteVector.fromValidHex(sign.toString("hex")))

  def verify[F[_]: Monad](
    pubKey: KeyPair.Public,
    signature: Signature,
    message: ByteVector
  ): EitherT[F, CryptoError, Unit] =
    for {
      hash ← JsCryptoHasher.hash(message, hasher)
      verify ← nonFatalHandling(
        Supercop.verify(signature.sign.toJsBuffer, ByteVector(hash).toJsBuffer, pubKey.value.toJsBuffer)
      )("Cannot verify message")
      _ ← EitherT.cond[F](verify, (), CryptoError("Signature is not verified"))
    } yield ()

  val generateKeyPair: Crypto.KeyPairGenerator =
    new Crypto.Func[Option[Array[Byte]], KeyPair] {
      override def apply[F[_]](
        input: Option[Array[Byte]]
      )(implicit F: Monad[F]): EitherT[F, CryptoError, KeyPair] = {
        for {
          seed ← nonFatalHandling(input.map(ByteVector(_).toJsBuffer).getOrElse(Supercop.createSeed()))(
            "Error on seed creation"
          )
          jsKeyPair ← nonFatalHandling(Supercop.createKeyPair(seed))("Error on key pair generation.")
          keyPair ← nonFatalHandling(
            KeyPair.fromByteVectors(
              ByteVector.fromValidHex(jsKeyPair.publicKey.toString("hex")),
              ByteVector.fromValidHex(jsKeyPair.secretKey.toString("hex"))
            )
          )("Error on decoding public and secret keys")
        } yield keyPair
      }
    }
}

object Ed25519 {

  val ed25519: Ed25519 = new Ed25519(Some(JsCryptoHasher.Sha256))

  val signAlgo: SignAlgo = {
    SignAlgo(
      name = "ed25519",
      generateKeyPair = ed25519.generateKeyPair,
      signer = kp ⇒
        Signer(
          kp.publicKey,
          new Crypto.Func[ByteVector, Signature] {
            override def apply[F[_]](
              input: ByteVector
            )(implicit F: Monad[F]): EitherT[F, CryptoError, Signature] =
              ed25519.sign(kp, input)
          }
      ),
      checker = pk ⇒
        new SignatureChecker {
          override def check[F[_]: Monad](
            signature: fluence.crypto.signature.Signature,
            plain: ByteVector
          ): EitherT[F, CryptoError, Unit] =
            ed25519.verify(pk, signature, plain)
      }
    )
  }
}
