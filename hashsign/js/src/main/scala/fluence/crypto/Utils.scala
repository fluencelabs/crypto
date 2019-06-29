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

import cats.Monad
import cats.data.EitherT
import io.scalajs.nodejs.buffer.Buffer
import scodec.bits.ByteVector

import scala.language.higherKinds
import scala.scalajs.js.JSConverters._
import scala.scalajs.js

object Utils {
  implicit class ByteVectorOp(bv: ByteVector) {
    def toJsBuffer: Buffer = Buffer.from(bv.toHex, "hex")
  }

  def hashJs[F[_]: Monad](message: ByteVector, hasher: Option[Crypto.Hasher[Array[Byte], Array[Byte]]]): EitherT[F, CryptoError, js.Array[Byte]] = {
    hash(message, hasher)
      .map(_.toJSArray)
  }

  def hash[F[_]: Monad](message: ByteVector, hasher: Option[Crypto.Hasher[Array[Byte], Array[Byte]]]): EitherT[F, CryptoError, Array[Byte]] = {
    val arr = message.toArray
    hasher
      .fold(EitherT.pure[F, CryptoError](arr)) { h ⇒
        h[F](arr)
      }
  }
}
