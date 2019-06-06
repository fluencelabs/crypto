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

import java.security._

import cats.Monad
import cats.data.EitherT
import fluence.crypto.KeyPair.Secret
import fluence.crypto.signature.{SignAlgo, SignatureChecker, Signer}
import fluence.crypto.{KeyPair, _}
import org.bouncycastle.crypto.KeyGenerationParameters
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.{Ed25519PrivateKeyParameters, Ed25519PublicKeyParameters}
import org.bouncycastle.crypto.signers.Ed25519Signer
import scodec.bits.ByteVector

import scala.language.higherKinds

/**
 * Edwards-curve Digital Signature Algorithm (EdDSA)
 */
class Ed25519(strength: Int) extends JavaAlgorithm {

  import CryptoError.nonFatalHandling

  val generateKeyPair: Crypto.KeyPairGenerator =
    new Crypto.Func[Option[Array[Byte]], KeyPair] {
      override def apply[F[_]](
        input: Option[Array[Byte]]
      )(implicit F: Monad[F]): EitherT[F, CryptoError, fluence.crypto.KeyPair] =
        for {
          g ← getKeyPairGenerator
          random = input.map(new SecureRandom(_)).getOrElse(new SecureRandom())
          keyParameters = new KeyGenerationParameters(random, strength)
          _ = g.init(keyParameters)
          p ← EitherT.fromOption(Option(g.generateKeyPair()), CryptoError("Generated key pair is null."))
          keyPair ← nonFatalHandling {
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
        } yield keyPair
    }

  /**
   * Restores pair of keys from the known secret key.
   * The public key will be the same each method call with the same secret key.
   * @param sk secret key
   * @return key pair
   */
  def restorePairFromSecret[F[_]: Monad](sk: Secret): EitherT[F, CryptoError, KeyPair] =
    for {
      keyPair ← nonFatalHandling {
        val secret = new Ed25519PrivateKeyParameters(sk.bytes, 0)
        KeyPair.fromBytes(secret.generatePublicKey().getEncoded, sk.bytes)
      }("Could not generate KeyPair from private key. Unexpected.")
    } yield keyPair

  def sign[F[_]: Monad](
    keyPair: KeyPair,
    message: ByteVector
  ): EitherT[F, CryptoError, signature.Signature] =
    signMessage(keyPair.secretKey.bytes, message.toArray)
      .map(bb ⇒ fluence.crypto.signature.Signature(ByteVector(bb)))

  def verify[F[_]: Monad](
    publicKey: KeyPair.Public,
    signature: fluence.crypto.signature.Signature,
    message: ByteVector
  ): EitherT[F, CryptoError, Unit] =
    verifySign(publicKey.bytes, signature.bytes, message.toArray)

  private def signMessage[F[_]: Monad](
    privateKey: Array[Byte],
    message: Array[Byte]
  ): EitherT[F, CryptoError, Array[Byte]] =
    for {
      sign ← nonFatalHandling {
        val privKey = new Ed25519PrivateKeyParameters(privateKey, 0)
        val signer = new Ed25519Signer
        signer.init(true, privKey)
        signer.update(message, 0, message.length)
        signer.generateSignature()
      }("Cannot sign message.")

    } yield sign

  private def verifySign[F[_]: Monad](
    publicKey: Array[Byte],
    signature: Array[Byte],
    message: Array[Byte],
  ): EitherT[F, CryptoError, Unit] =
    for {
      verify ← nonFatalHandling {
        val pubKey = new Ed25519PublicKeyParameters(publicKey, 0)
        val signer = new Ed25519Signer
        signer.init(false, pubKey)
        signer.update(message, 0, message.length)
        signer.verifySignature(signature)
      }("Cannot verify message.")

      _ ← EitherT.cond[F](verify, (), CryptoError("Signature is not verified"))
    } yield ()

  private def getKeyPairGenerator[F[_]: Monad] =
    nonFatalHandling {
      new Ed25519KeyPairGenerator()
    }(
      "Cannot get key pair generator."
    )
}

object Ed25519 {

  /**
   * Keys in tendermint are generating with a random seed of 32 bytes
   */
  val tendermintEd25519 = new Ed25519(256)
  val tendermintAlgo: SignAlgo = signAlgo(256)

  def ed25519(strength: Int) = new Ed25519(strength)

  def signAlgo(strength: Int): SignAlgo = {
    val algo = ed25519(strength)
    SignAlgo(
      name = "ed25519",
      generateKeyPair = algo.generateKeyPair,
      signer = kp ⇒
        Signer(
          kp.publicKey,
          new Crypto.Func[ByteVector, signature.Signature] {
            override def apply[F[_]](
              input: ByteVector
            )(implicit F: Monad[F]): EitherT[F, CryptoError, signature.Signature] =
              algo.sign(kp, input)
          }
      ),
      checker = pk ⇒
        new SignatureChecker {
          override def check[F[_]: Monad](
            signature: fluence.crypto.signature.Signature,
            plain: ByteVector
          ): EitherT[F, CryptoError, Unit] =
            algo.verify(pk, signature, plain)
      }
    )
  }
}
