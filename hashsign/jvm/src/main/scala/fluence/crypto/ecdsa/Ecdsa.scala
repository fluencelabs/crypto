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

import java.math.BigInteger
import java.security._
import java.security.interfaces.ECPrivateKey

import cats.instances.either._
import cats.syntax.either._
import fluence.crypto.KeyPair.Secret
import fluence.crypto.{KeyPair, _}
import fluence.crypto.hash.JdkCryptoHasher
import fluence.crypto.signature.{SignAlgo, SignatureChecker, Signer}
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.interfaces.ECPublicKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.{ECParameterSpec, ECPrivateKeySpec, ECPublicKeySpec}
import scodec.bits.ByteVector

import scala.language.higherKinds

/**
 * Elliptic Curve Digital Signature Algorithm
 * @param curveType http://www.bouncycastle.org/wiki/display/JA1/Supported+Curves+%28ECDSA+and+ECGOST%29
 * @param scheme https://bouncycastle.org/specifications.html
 */
class Ecdsa(curveType: String, scheme: String, hasher: Option[Crypto.Hasher[Array[Byte], Array[Byte]]])
    extends JavaAlgorithm {

  import Ecdsa._

  val HEXradix = 16

  /**
   * Restores pair of keys from the known secret key.
   * The public key will be the same each method call with the same secret key.
   * sk secret key
   * @return key pair
   */
  val restorePairFromSecret: Crypto.Func[Secret, KeyPair] =
    Crypto(
      sk ⇒
        for {
          ecSpec ← Either.fromOption(
            Option(ECNamedCurveTable.getParameterSpec(curveType)),
            CryptoError("Parameter spec for the curve is not available.")
          )
          keyPair ← Crypto.tryUnit {
            val hex = sk.value.toHex
            val d = new BigInteger(hex, HEXradix)
            // to re-create public key from private we need to multiply known from curve point G with D (private key)
            // result will be point Q (public key)
            // https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
            val g = ecSpec.getG
            val q = g.multiply(d)
            val pk = ByteVector(q.getEncoded(true))
            KeyPair.fromByteVectors(pk, sk.value)
          }("Could not generate KeyPair from private key. Unexpected.")
        } yield keyPair
    )

  private def curveSpec: Crypto.Result[ECParameterSpec] =
    Crypto.tryUnit(ECNamedCurveTable.getParameterSpec(curveType).asInstanceOf[ECParameterSpec])(
      "Cannot get curve parameters"
    )

  private def getKeyPairGenerator =
    Crypto.tryUnit(KeyPairGenerator.getInstance(ECDSA, BouncyCastleProvider.PROVIDER_NAME))(
      "Cannot get key pair generator"
    )

  val generateKeyPair: Crypto.KeyPairGenerator =
    Crypto[Option[Array[Byte]], KeyPair] { input ⇒
      for {
        ecSpec ← Either.fromOption(
          Option(ECNamedCurveTable.getParameterSpec(curveType)),
          CryptoError("Parameter spec for the curve is not available.")
        )
        g ← getKeyPairGenerator
        _ ← Crypto.tryUnit {
          g.initialize(ecSpec, input.map(new SecureRandom(_)).getOrElse(new SecureRandom()))
        }(s"Could not initialize KeyPairGenerator")
        p ← Either.fromOption(Option(g.generateKeyPair()), CryptoError("Generated key pair is null"))
        keyPair ← Crypto.tryUnit {
          val pk = p.getPublic match {
            case pk: ECPublicKey => ByteVector(p.getPublic.asInstanceOf[ECPublicKey].getQ.getEncoded(true))
            case p =>
              throw new ClassCastException(s"Cannot cast public key (${p.getClass}) to Ed25519PublicKeyParameters")
          }
          val sk = p.getPrivate match {
            case sk: ECPrivateKey =>
              val bg = p.getPrivate.asInstanceOf[ECPrivateKey].getS
              ByteVector.fromValidHex(bg.toString(HEXradix))
            case s =>
              throw new ClassCastException(s"Cannot cast private key (${p.getClass}) to Ed25519PrivateKeyParameters")
          }
          KeyPair.fromByteVectors(pk, sk)
        }("Could not generate KeyPair")
      } yield keyPair
    }

  private def getKeyFactory =
    Crypto.tryUnit(KeyFactory.getInstance(ECDSA, BouncyCastleProvider.PROVIDER_NAME))(
      "Cannot get key factory instance"
    )

  private def getSignatureProvider =
    Crypto.tryUnit(Signature.getInstance(scheme, BouncyCastleProvider.PROVIDER_NAME))(
      "Cannot get signature instance"
    )

  private val signMessage: Crypto.Func[(BigInteger, Array[Byte]), Array[Byte]] =
    Crypto {
      case (
          privateKey,
          message
          ) ⇒
        for {
          ec ← curveSpec
          keySpec ← Crypto.tryUnit(new ECPrivateKeySpec(privateKey, ec))("Cannot read private key.")
          keyFactory ← getKeyFactory
          signProvider ← getSignatureProvider
          _ ← Crypto.tryUnit(signProvider.initSign(keyFactory.generatePrivate(keySpec)))("Cannot initSign")
          hash ← hasher.fold(
            message.asRight[CryptoError]
          )(_.apply(message))

          sign ← Crypto.tryUnit {
            signProvider.update(hash)
            signProvider.sign()
          }("Cannot sign message.")

        } yield sign
    }

  val sign: Crypto.Func[(KeyPair, ByteVector), signature.Signature] =
    signMessage
      .map(bb ⇒ fluence.crypto.signature.Signature(ByteVector(bb)))
      .local {
        case (keyPair, message) ⇒ (new BigInteger(keyPair.secretKey.value.toHex, HEXradix), message.toArray)
      }

  private val verifySign: Crypto.Func[(Array[Byte], Array[Byte], Array[Byte]), Unit] =
    Crypto {
      case (
          publicKey,
          signature,
          message
          ) ⇒
        for {
          ec ← curveSpec
          keySpec ← Crypto.tryUnit(new ECPublicKeySpec(ec.getCurve.decodePoint(publicKey), ec))(
            "Cannot read public key"
          )
          keyFactory ← getKeyFactory
          signProvider ← getSignatureProvider
          _ ← Crypto.tryUnit(
            signProvider.initVerify(keyFactory.generatePublic(keySpec))
          )("Cannot initVerify message")

          hash ← hasher.fold(
            message.asRight[CryptoError]
          )(_.apply(message))

          _ ← Crypto.tryUnit(signProvider.update(hash))("Cannot update message")

          verify ← Crypto.tryUnit(signProvider.verify(signature))("Cannot verify message")

          _ ← Either.cond(verify, (), CryptoError("Signature is not verified"))
        } yield ()
    }

  val verify: Crypto.Func[(KeyPair.Public, signature.Signature, ByteVector), Unit] =
    verifySign.local {
      case (
          publicKey,
          signature,
          message
          ) ⇒
        (publicKey.bytes, signature.bytes, message.toArray)
    }
}

object Ecdsa {
  //algorithm name in security provider
  val ECDSA = "ECDSA"

  /**
   * size of key is 256 bit
   * `secp256k1` refers to the parameters of the ECDSA curve
   * `NONEwithECDSA with sha-256 hasher` Preferably the size of the key is greater than or equal to the digest algorithm
   * don't use `SHA256WithECDSA` because of non-compatibility with javascript libraries
   */
  val ecdsa_secp256k1_sha256 = new Ecdsa("secp256k1", "NONEwithECDSA", Some(JdkCryptoHasher.Sha256))

  val signAlgo: SignAlgo = SignAlgo(
    name = "ecdsa_secp256k1_sha256",
    generateKeyPair = ecdsa_secp256k1_sha256.generateKeyPair,
    signer = kp ⇒
      Signer(
        kp.publicKey,
        Crypto { input ⇒
          ecdsa_secp256k1_sha256.sign(kp -> input)
        }
      ),
    checker = pk ⇒
      SignatureChecker(
        Crypto {
          case (
              signature: fluence.crypto.signature.Signature,
              plain: ByteVector
              ) ⇒
            ecdsa_secp256k1_sha256.verify(pk, signature, plain)
        }
      )
  )
}
