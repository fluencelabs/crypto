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

package fluence.crypto.cipher

import cats.Monad
import cats.data.Kleisli
import fluence.crypto.Crypto
import cats.instances.either._
import cats.syntax.either._

import scala.collection.Searching.{Found, InsertionPoint, SearchResult}
import scala.language.higherKinds

object CipherSearch {

  /**
   * Searches the specified indexedSeq for the search element using the binary search algorithm.		
   * The sequence should be sorted with the same `Ordering` before calling, otherwise, the results are undefined.		
   *		
   * @param coll       Ordered collection of encrypted elements to search in.
   * @param decrypt    Decryption function for sequence elements.
   * @param ordering   The ordering to be used to compare elements.		
   *		
   * @return A `Found` value containing the index corresponding to the search element in the		
   *         sequence. A `InsertionPoint` value containing the index where the element would be inserted if		
   *         the search element is not found in the sequence.		
   */
  def binarySearch[A, B](coll: IndexedSeq[A], decrypt: Crypto.Func[A, B])(
    implicit ordering: Ordering[B]
  ): Crypto.Func[B, SearchResult] =
    Kleisli {
      input ⇒ {
        implicitly[Monad[Crypto.Err]].tailRecM((0, coll.length)) {
          case (from, to) if from == to ⇒ Right(InsertionPoint(from)).asRight
          case (from, to) ⇒
            val idx = from + (to - from - 1) / 2
            decrypt(coll(idx)).map { d ⇒
              math.signum(ordering.compare(input, d)) match {
                case -1 ⇒ Left((from, idx))
                case 1 ⇒ Left((idx + 1, to))
                case _ ⇒ Right(Found(idx))
              }
            }
        }
      }
    }
}
