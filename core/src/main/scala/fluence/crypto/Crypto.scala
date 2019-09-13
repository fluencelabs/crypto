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

import cats.data.Kleisli

import scala.util.Try

object Crypto {
  type Result[T] = Either[CryptoError, T]

  type Hasher[A, B] = Kleisli[Result, A, B]

  type Func[A, B] = Kleisli[Result, A, B]

  case class Cipher[A](
    encrypt: Kleisli[Result, A, Array[Byte]],
    decrypt: Kleisli[Result, Array[Byte], A]
  )

  type KeyPairGenerator = Kleisli[Result, Option[Array[Byte]], KeyPair]

  def apply[A, B](fn: A ⇒ Result[B]): Func[A, B] = Kleisli[Result, A, B](fn)

  def tryFn[A, B](fn: A ⇒ B)(errorText: String): Crypto.Func[A, B] =
    Crypto(a ⇒ tryUnit(fn(a))(errorText))

  def tryUnit[B](fn: ⇒ B)(errorText: String): Result[B] =
    Try(fn).toEither.left.map(t ⇒ CryptoError(errorText, Some(t)))

  def cond[B](ifTrue: ⇒ B, errorText: ⇒ String): Crypto.Func[Boolean, B] =
    Crypto(Either.cond(_, ifTrue, CryptoError(errorText)))
}
