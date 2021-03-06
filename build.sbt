import de.heikoseeberger.sbtheader.License
import org.scalajs.sbtplugin.ScalaJSPlugin.autoImport._
import sbtcrossproject.CrossPlugin.autoImport.crossProject

name := "crypto"

scalacOptions in Compile ++= Seq("-Ypartial-unification", "-Xdisable-assertions")

javaOptions in Test ++= Seq("-ea")

skip in publish := true // Skip root project

val scalaV = scalaVersion := "2.12.9"

val commons = Seq(
  scalaV,
  version                   := "0.1.0",
  fork in Test              := true,
  parallelExecution in Test := false,
  organization              := "one.fluence",
  organizationName          := "Fluence Labs Limited",
  organizationHomepage      := Some(new URL("https://fluence.one")),
  startYear                 := Some(2017),
  licenses += ("AGPL-V3", new URL("http://www.gnu.org/licenses/agpl-3.0.en.html")),
  headerLicense       := Some(License.AGPLv3("2017", organizationName.value)),
  bintrayOrganization := Some("fluencelabs"),
  publishMavenStyle   := true,
  scalafmtOnCompile   := true,
  bintrayRepository   := "releases",
  resolvers ++= Seq(Resolver.bintrayRepo("fluencelabs", "releases"), Resolver.sonatypeRepo("releases"))
)

commons

val CatsV = "2.0.0"
val CirceV = "0.12.1"

val SloggingV = "0.6.1"

val ScalatestV = "3.0.+"

val bouncyCastle = "org.bouncycastle" % "bcprov-jdk15on" % "1.61"

enablePlugins(AutomateHeaderPlugin)

lazy val `crypto-core` = crossProject(JVMPlatform, JSPlatform)
  .withoutSuffixFor(JVMPlatform)
  .crossType(FluenceCrossType)
  .in(file("core"))
  .settings(
    commons,
    libraryDependencies ++= Seq(
      "org.scodec" %%% "scodec-core" % "1.11.3",
      "org.typelevel" %%% "cats-core" % CatsV,
      "org.scalatest" %%% "scalatest"  % ScalatestV % Test
    )
  )
  .jsSettings(
    fork in Test := false
  )
  .enablePlugins(AutomateHeaderPlugin)

lazy val `crypto-core-js` = `crypto-core`.js
lazy val `crypto-core-jvm` = `crypto-core`.jvm

lazy val `crypto-hashsign` = crossProject(JVMPlatform, JSPlatform)
  .withoutSuffixFor(JVMPlatform)
  .crossType(FluenceCrossType)
  .in(file("hashsign"))
  .settings(
    commons,
    libraryDependencies ++= Seq(
      "org.scalatest" %%% "scalatest" % ScalatestV % Test
    )
  )
  .jvmSettings(
    libraryDependencies ++= Seq(
      //JVM-specific provider for cryptography
      bouncyCastle
    )
  )
  .jsSettings(
    libraryDependencies += "io.scalajs" %%% "nodejs" % "0.4.2",
    npmDependencies in Compile ++= Seq(
      "elliptic" -> "6.4.1",
      "supercop.js" -> "2.0.1",
      "hash.js" -> "1.1.7"
    ),
    scalaJSModuleKind in Test := ModuleKind.CommonJSModule,
    //all JavaScript dependencies will be concatenated to a single file *-jsdeps.js
    skip in packageJSDependencies := false,
    fork in Test                  := false
  )
  .enablePlugins(AutomateHeaderPlugin)
  .dependsOn(`crypto-core`)

lazy val `crypto-hashsign-js` = `crypto-hashsign`.js
  .enablePlugins(ScalaJSBundlerPlugin)
lazy val `crypto-hashsign-jvm` = `crypto-hashsign`.jvm

lazy val `crypto-cipher` = crossProject(JVMPlatform, JSPlatform)
  .withoutSuffixFor(JVMPlatform)
  .crossType(FluenceCrossType)
  .in(file("cipher"))
  .settings(
    commons,
    libraryDependencies ++= Seq(
      "biz.enef"      %%% "slogging"  % SloggingV % Test,
      "org.scalatest" %%% "scalatest" % ScalatestV % Test
    )
  )
  .jvmSettings(
    libraryDependencies ++= Seq(
      //JVM-specific provider for cryptography
      bouncyCastle
    )
  )
  .jsSettings(
    npmDependencies in Compile ++= Seq(
      "crypto-js" -> "3.1.9-1"
    ),
    //all JavaScript dependencies will be concatenated to a single file *-jsdeps.js
    skip in packageJSDependencies := false,
    fork in Test                  := false,
    scalaJSModuleKind             := ModuleKind.CommonJSModule
  )
  .enablePlugins(AutomateHeaderPlugin)
  .dependsOn(`crypto-hashsign`)

lazy val `crypto-cipher-js` = `crypto-cipher`.js
  .enablePlugins(ScalaJSBundlerPlugin)
lazy val `crypto-cipher-jvm` = `crypto-cipher`.jvm
