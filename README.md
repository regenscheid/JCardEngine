# Classical PIV simulator baseline

The `main` branch contains the classical simulator used with the companion
OpenFIPS201 applet and piv-test tools. Experimental post-quantum extensions are
maintained separately on `pqc`.

Build and run the local test suite on macOS or Ubuntu with Git, curl (or wget), and a JDK 17 or newer:

```sh
git clone --branch main --recurse-submodules https://github.com/regenscheid/JCardEngine.git
cd JCardEngine
./scripts/build.sh
java -jar tool/target/jcard.jar --help
```

The build initializes the pinned Java Card SDK submodule, installs its API JARs,
runs the simulator tests, verifies test CAPs, and creates `tool/target/jcard.jar`.
GlobalPlatformPro is pinned to published version `26.06.04`; the CAP build uses
ant-javacard `v26.05.15` with a checked SHA-256 digest. Build tools and test
outputs are generated locally. `JAVA_HOME` may select another supported JDK.

Inherited GitHub workflows have manual triggers only while local validation is
being established. The complete applet/provisioning smoke test is in piv-test:
`python tools/stack.py smoke` after building its pinned stack.

## Upstream project



[![Latest release](https://img.shields.io/github/release/martinpaljak/jcardengine/all.svg)](https://github.com/martinpaljak/jcardengine/releases/latest)
&nbsp;[![Maven version](https://img.shields.io/maven-metadata/v?label=maven&metadataUrl=https%3A%2F%2Fmvn.javacard.pro%2Fmaven%2FSNAPSHOTS%2Fcom%2Fgithub%2Fmartinpaljak%2Fjcardengine%2Fmaven-metadata.xml)](https://gist.github.com/martinpaljak/c77d11d671260e24eef6c39123345cae)
&nbsp;[![Apache 2.0 licensed](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/martinpaljak/jcardengine/blob/master/LICENSE)
&nbsp;[![Build status](https://github.com/martinpaljak/jcardengine/actions/workflows/robot.yml/badge.svg?branch=next)](https://github.com/martinpaljak/jcardengine/actions)
&nbsp;[![Made in Estonia](https://img.shields.io/badge/Made_in-Estonia-0072CE?style=flat&label=Made%20in&labelColor=black)](https://estonia.ee)

# JCardEngine - Java Card Runtime Engine for Java.

Run JavaCard applet source code without a physical device.

> [!TIP]
> More information on how to build and use is available in the [Wiki](https://github.com/martinpaljak/jcardengine/wiki).

<sub>This is a fork/rewrite of [@licel/jcardsim](https://github.com/licel/jcardsim) from April 3, 2024 revision `aa60a02f042c18211e4d0f0aef75f27b0e5cf873`.</sub>

<sub>NOTE: Oracle and Java are trademarks of Oracle Corporation.</sub>
