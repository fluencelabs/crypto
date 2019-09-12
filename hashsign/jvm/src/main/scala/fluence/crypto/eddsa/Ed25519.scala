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

import java.security._

import cats.syntax.either._
import cats.instances.either._
import cats.syntax.functor._
import fluence.crypto.KeyPair.Secret
import fluence.crypto.signature.{SignAlgo, SignatureChecker, Signer}
import fluence.crypto.{KeyPair, _}
import org.bouncycastle.crypto.{AsymmetricCipherKeyPair, KeyGenerationParameters}
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.{Ed25519PrivateKeyParameters, Ed25519PublicKeyParameters}
import org.bouncycastle.crypto.signers.Ed25519Signer
import scodec.bits.ByteVector

import scala.language.higherKinds

/**
 * Edwards-curve Digital Signature Algorithm (EdDSA)
 */
class Ed25519(strength: Int) extends JavaAlgorithm {

  /**
   * Restores pair of keys from the known secret key.
   * The public key will be the same each method call with the same secret key.
   * sk secret key
   * @return key pair
   */
  val restorePairFromSecret: Crypto.Func[Secret, KeyPair] =
    Crypto.tryFn[Secret, KeyPair] {
      sk ⇒
        val secret = new Ed25519PrivateKeyParameters(sk.bytes, 0)
        KeyPair.fromBytes(secret.generatePublicKey().getEncoded, sk.bytes)
      }("Could not generate KeyPair from private key")

  private val signMessage: Crypto.Func[(Array[Byte], Array[Byte]), Array[Byte]] =
    Crypto.tryFn[(Array[Byte], Array[Byte]), Array[Byte]] {
      case (
        privateKey,
        message
        ) ⇒
        val privKey = new Ed25519PrivateKeyParameters(privateKey, 0)
        val signer = new Ed25519Signer
        signer.init(true, privKey)
        signer.update(message, 0, message.length)
        signer.generateSignature()
      }("Cannot sign message")

  val sign: Crypto.Func[(KeyPair, ByteVector), signature.Signature] =
    signMessage
      .map(bb ⇒ fluence.crypto.signature.Signature(ByteVector(bb)))
      .local {
          case  (keyPair, message) ⇒
            keyPair.secretKey.bytes -> message.toArray
        }

  private val verifySign: Crypto.Func[(Array[Byte], Array[Byte], Array[Byte]), Unit] =
    Crypto.tryFn[(Array[Byte], Array[Byte], Array[Byte]), Boolean] {
        case (
          publicKey,
          signature,
          message,
          ) ⇒
        val pubKey = new Ed25519PublicKeyParameters(publicKey, 0)
        val signer = new Ed25519Signer
        signer.init(false, pubKey)
        signer.update(message, 0, message.length)
        signer.verifySignature(signature)
      }("Cannot verify message") andThen Crypto.cond((), "Signature is not verified")

  val verify: Crypto.Func[(KeyPair.Public, signature.Signature, ByteVector), Unit] =
    verifySign
        .local {
          case (
            publicKey,
            signature,
            message
            ) ⇒
            (publicKey.bytes, signature.bytes, message.toArray)
        }

  private def getKeyPairGenerator =
    Crypto.tryUnit(
      new Ed25519KeyPairGenerator()
    )(
      "Cannot get key pair generator"
    )

  val generateKeyPair: Crypto.KeyPairGenerator =
    Crypto[Option[Array[Byte]], KeyPair] {
      input ⇒
        getKeyPairGenerator.flatMap {g ⇒
          val random = input.map(new SecureRandom(_)).getOrElse(new SecureRandom())
          val keyParameters = new KeyGenerationParameters(random, strength)
          g.init(keyParameters)
          Either.fromOption(Option(g.generateKeyPair()), CryptoError("Generated keypair is null"))
        }.flatMap((p: AsymmetricCipherKeyPair) ⇒
          Crypto.tryUnit {
              val pk = p.getPublic match {
                case pk: Ed25519PublicKeyParameters => pk.getEncoded
                case p => throw new ClassCastException(s"Cannot cast public key (${p.getClass}) to Ed25519PublicKeyParameters")
              }
              val sk = p.getPrivate match {
                case sk: Ed25519PrivateKeyParameters => sk.getEncoded
                case s => throw new ClassCastException(s"Cannot cast private key (${p.getClass}) to Ed25519PrivateKeyParameters")
              }
              KeyPair.fromBytes(pk, sk)
          }("Could not generate KeyPair")
        )
    }
}

object Ed25519 {

  /**
   * Keys in tendermint are generating with a random seed of 32 bytes
   */
  val ed25519 = new Ed25519(256)
  val signAlgo: SignAlgo = signAlgoInit(256)

  /**
   *
   * @param strength the size, in bits, of the keys we want to produce
   */
  def ed25519Init(strength: Int) = new Ed25519(strength)

  /**
   *
   * @param strength the size, in bits, of the keys we want to produce
   */
  def signAlgoInit(strength: Int): SignAlgo = {
    val algo = ed25519Init(strength)
    SignAlgo(
      name = "ed25519",
      generateKeyPair = algo.generateKeyPair,
      signer = kp ⇒
        Signer(
          kp.publicKey,
          Crypto[ByteVector, signature.Signature] {
            input ⇒
              algo.sign(kp -> input)
          }
      ),
      checker = pk ⇒
        SignatureChecker(
          Crypto {
            case (signature, plain) ⇒
              algo.verify(pk, signature, plain)
          }
        )
    )
  }
}
