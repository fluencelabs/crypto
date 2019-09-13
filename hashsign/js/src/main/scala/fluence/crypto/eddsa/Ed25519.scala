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

import fluence.crypto.facade.ed25519.Supercop
import fluence.crypto.hash.JsCryptoHasher
import fluence.crypto.{Crypto, CryptoError, CryptoJsHelpers, KeyPair}
import fluence.crypto.signature.{SignAlgo, Signature, SignatureChecker, Signer}
import scodec.bits.ByteVector

import scala.language.higherKinds

class Ed25519(hasher: Option[Crypto.Hasher[Array[Byte], Array[Byte]]]) {

  import CryptoJsHelpers._

  val sign: Crypto.Func[(KeyPair, ByteVector), Signature] =
    Crypto {
      case (keyPair, message) ⇒
        for {
          hash ← JsCryptoHasher.hash(message, hasher)
          sign ← Crypto.tryUnit {
            Supercop.sign(
              ByteVector(hash).toJsBuffer,
              keyPair.publicKey.value.toJsBuffer,
              keyPair.secretKey.value.toJsBuffer
            )
          }("Error on signing message by js/ed25519 signature")
        } yield Signature(ByteVector.fromValidHex(sign.toString("hex")))
    }

  val verify: Crypto.Func[(KeyPair.Public, Signature, ByteVector), Unit] =
    Crypto {
      case (
          pubKey,
          signature,
          message
          ) ⇒
        for {
          hash ← JsCryptoHasher.hash(message, hasher)
          verify ← Crypto.tryUnit(
            Supercop.verify(signature.sign.toJsBuffer, ByteVector(hash).toJsBuffer, pubKey.value.toJsBuffer)
          )("Cannot verify message")
          _ ← Either.cond(verify, (), CryptoError("Signature is not verified"))
        } yield ()
    }

  val generateKeyPair: Crypto.KeyPairGenerator =
    Crypto[Option[Array[Byte]], KeyPair] { input ⇒
      for {
        seed ← Crypto.tryUnit(input.map(ByteVector(_).toJsBuffer).getOrElse(Supercop.createSeed()))(
          "Error on seed creation"
        )
        jsKeyPair ← Crypto.tryUnit(Supercop.createKeyPair(seed))("Error on key pair generation.")
        keyPair ← Crypto.tryUnit(
          KeyPair.fromByteVectors(
            ByteVector.fromValidHex(jsKeyPair.publicKey.toString("hex")),
            ByteVector.fromValidHex(jsKeyPair.secretKey.toString("hex"))
          )
        )("Error on decoding public and secret keys")
      } yield keyPair
    }
}

object Ed25519 {

  val ed25519: Ed25519 = new Ed25519(None)

  val signAlgo: SignAlgo =
    SignAlgo(
      name = "ed25519",
      generateKeyPair = ed25519.generateKeyPair,
      signer = kp ⇒
        Signer(
          kp.publicKey,
          ed25519.sign.local(kp -> _)
        ),
      checker = pk ⇒
        SignatureChecker(
          ed25519.verify.local {
            case (signature, plain) ⇒ (pk, signature, plain)
          }
        )
    )

}
