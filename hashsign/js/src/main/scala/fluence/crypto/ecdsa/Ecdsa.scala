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

package fluence.crypto.ecdsa

import fluence.crypto._
import fluence.crypto.facade.ecdsa.EC
import fluence.crypto.hash.JsCryptoHasher
import fluence.crypto.signature.{SignAlgo, Signature, SignatureChecker, Signer}
import scodec.bits.ByteVector

import scala.language.higherKinds
import scala.scalajs.js
import scala.scalajs.js.JSConverters._
import scala.scalajs.js.typedarray.Uint8Array

/**
 * Return in all js methods hex, because in the other case we will receive javascript objects
 * @param ec implementation of ecdsa logic for different curves
 */
class Ecdsa(ec: EC, hasher: Option[Crypto.Hasher[Array[Byte], Array[Byte]]]) {

  /**
   * Restores key pair by secret key.
   *
   */
  val restoreKeyPair: Crypto.Func[KeyPair.Secret, KeyPair] =
    Crypto.tryFn[KeyPair.Secret, KeyPair] {secretKey ⇒
        val key = ec.keyFromPrivate(secretKey.value.toHex, "hex")
        val publicHex = key.getPublic(compact = true, "hex")
        val secretHex = key.getPrivate("hex")
        val public = ByteVector.fromValidHex(publicHex)
        val secret = ByteVector.fromValidHex(secretHex)
        KeyPair.fromByteVectors(public, secret)
      }("Incorrect secret key format")

  val generateKeyPair: Crypto.KeyPairGenerator =
    Crypto.tryFn[Option[Array[Byte]], KeyPair] {input ⇒
          val seedJs = input.map(bs ⇒ js.Dynamic.literal(entropy = bs.toJSArray))
          val key = ec.genKeyPair(seedJs)
          val publicHex = key.getPublic(compact = true, "hex")
          val secretHex = key.getPrivate("hex")
          val public = ByteVector.fromValidHex(publicHex)
          val secret = ByteVector.fromValidHex(secretHex)
          KeyPair.fromByteVectors(public, secret)
        }("Failed to generate key pair")

  val sign: Crypto.Func[(KeyPair, ByteVector), Signature] =
    Crypto {
      case (keyPair: KeyPair, message: ByteVector) ⇒
        for {
          secret ← Crypto.tryUnit {
            ec.keyFromPrivate(keyPair.secretKey.value.toHex, "hex")
          }("Cannot get private key from key pair")
          hash ← JsCryptoHasher.hashJs(message, hasher)
          signHex ← Crypto.tryUnit(secret.sign(new Uint8Array(hash)).toDER("hex"))("Cannot sign message")
        } yield Signature(ByteVector.fromValidHex(signHex))
    }

  val verify: Crypto.Func[(KeyPair.Public, Signature, ByteVector), Unit] =
    Crypto {
      case (
        pubKey,
        signature,
        message
      ) ⇒
        for {
          public ← Crypto.tryUnit {
            val hex = pubKey.value.toHex
            ec.keyFromPublic(hex, "hex")
          }("Incorrect public key format.")
          hash ← JsCryptoHasher.hashJs(message, hasher)
          verify ← Crypto.tryUnit(public.verify(new Uint8Array(hash), signature.sign.toHex))("Cannot verify message")
          _ ← Either.cond(verify, (), CryptoError("Signature is not verified"))
        } yield ()
    }

}

object Ecdsa {
  val ecdsa_secp256k1_sha256 = new Ecdsa(new EC("secp256k1"), Some(JsCryptoHasher.Sha256))

  val signAlgo: SignAlgo = SignAlgo(
    "ecdsa/secp256k1/sha256/js",
    generateKeyPair = ecdsa_secp256k1_sha256.generateKeyPair,
    signer = kp ⇒
      Signer(
        kp.publicKey,
            ecdsa_secp256k1_sha256.sign.local(kp -> _)
    ),
    checker = pk ⇒
      SignatureChecker (
          ecdsa_secp256k1_sha256.verify.local{
            case (signature, plain) ⇒ (pk, signature, plain)
          }
      )
  )
}
