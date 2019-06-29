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

package fluence.crypto.ed25519

import cats.Monad
import cats.data.EitherT
import fluence.crypto.CryptoError.nonFatalHandling
import fluence.crypto.facade.ed25519.Supercop
import fluence.crypto.{Crypto, CryptoError, KeyPair, Utils}
import fluence.crypto.signature.Signature
import io.scalajs.nodejs.buffer.Buffer
import scodec.bits.ByteVector

import scala.language.higherKinds

class Ed25519(hasher: Option[Crypto.Hasher[Array[Byte], Array[Byte]]]) {

  import Utils._

  def sign[F[_]: Monad](keyPair: KeyPair, message: ByteVector): EitherT[F, CryptoError, Signature] =
    for {
      hash ← Utils.hash(message, hasher)
      sign ← nonFatalHandling {
        Supercop.sign(Buffer.from(ByteVector(hash).toHex, "hex"), keyPair.publicKey.value.toJsBuffer, keyPair.secretKey.value.toJsBuffer)
      }("Error on signing message. Ed25519")
    } yield Signature(ByteVector.fromValidHex(sign.toString("hex")))

  def verify[F[_]: Monad](
    pubKey: KeyPair.Public,
    signature: Signature,
    message: ByteVector
  ): EitherT[F, CryptoError, Unit] =
    for {
      hash ← Utils.hash(message, hasher)
      verify ← nonFatalHandling(Supercop.verify(signature.sign.toJsBuffer, ByteVector(hash).toJsBuffer, pubKey.value.toJsBuffer))("Cannot verify message.")
      _ ← EitherT.cond[F](verify, (), CryptoError("Signature is not verified"))
    } yield ()

  val generateKeyPair: Crypto.KeyPairGenerator = ???
}