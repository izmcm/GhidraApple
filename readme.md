# GhidraApple

Ghidra extension for macOS/iOS binary analysis.

Supported Ghidra versions: **12.1.3** and **12.1.2**.

---

## Installation (no build required)

If you just want to use the extension, **don't clone or build anything** — grab the ready-made `.zip` from the [Releases page](https://github.com/izmcm/GhidraApple/releases) and install it.

1. Open the [latest release](https://github.com/izmcm/GhidraApple/releases/latest)
2. Download the `.zip` matching your Ghidra version, e.g. `ghidra_12.1.3_PUBLIC_<date>_GhidraApple.zip`
3. Install it, either way:

**Via Ghidra UI (recommended)**

- Open Ghidra
- `File > Install Extensions`
- Click `+`, select the downloaded `.zip`
- Restart Ghidra

**By hand (unzip into the Ghidra folder)**

```bash
unzip ghidra_12.1.3_PUBLIC_<date>_GhidraApple.zip \
  -d /path/to/ghidra_12.1.3_PUBLIC/Ghidra/Extensions/
```

This leaves a `GhidraApple/` folder inside `Ghidra/Extensions/`. Restart Ghidra, then enable it in `File > Configure`.

> The `.zip` must match your Ghidra version — Ghidra refuses extensions built for a different release.

To uninstall, uncheck it in `File > Install Extensions`, or delete `Ghidra/Extensions/GhidraApple`.

---

# Development Setup

Only needed if you want to change the extension's code.

## Requirements

| Tool | Version | Notes |
|---|---|---|
| Java (Temurin) | 21 | Required — other distributions may cause issues |
| Gradle | 8.10 | Via Gradle Wrapper (`./gradlew`) |
| Ghidra | 12.1.3 or 12.1.2 | |
| IntelliJ IDEA | Any recent | Community Edition is sufficient |

---

## 1. Java 21 Temurin via SDKMAN

Install [SDKMAN](https://sdkman.io) if you don't have it:

```bash
curl -s "https://get.sdkman.io" | bash
source "$HOME/.sdkman/bin/sdkman-init.sh"
```

Install and set Java 21 Temurin:

```bash
sdk install java 21.0.5-tem
sdk use java 21.0.5-tem
```

Verify:

```bash
java -version
# Expected: openjdk version "21.x.x" ... Temurin
```

---

## 2. Ghidra Environment Variable

Gradle needs to know where Ghidra is installed. Add to your `~/.zshrc` or `~/.bashrc`:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.3_PUBLIC
```

Reload and confirm:

```bash
source ~/.zshrc
echo $GHIDRA_INSTALL_DIR
ls $GHIDRA_INSTALL_DIR/Ghidra  # should list Ghidra's internal folders
```

---

## 3. Clone and Build

```bash
git clone https://github.com/ReverseApple/GhidraApple.git
cd GhidraApple

# Build the extension (generates a .zip in dist/)
./gradlew buildExtension
```

The output artifact will be at:
```
dist/ghidra_12.1.3_PUBLIC_<date>_GhidraApple.zip
```

---

## 4. IntelliJ IDEA Setup

The project already includes run configurations under `.idea/runConfigurations/` to launch and debug Ghidra directly from IntelliJ.

### Generate project files

```bash
./gradlew idea
```

Open the project root in IntelliJ. The Ghidra classpath will be resolved automatically via `GHIDRA_INSTALL_DIR`.

### Set the SDK in IntelliJ

1. `File > Project Structure > SDK`
2. Add the Java 21 Temurin installed in step 1
3. Confirm the `Project SDK` is pointing to it

---

## 5. Running Tests

```bash
./gradlew test
```

Some tests require an actual binary to analyze and are skipped by default. To run them, pass the binary path via environment variable:

```bash
PATH_TO_BINARY_WITH_BLOCKS=/path/to/your-macho ./gradlew test
```

Or set it permanently in IntelliJ via `Run > Edit Configurations > Environment Variables`.

Tests that depend on external binaries use JUnit's `assumeTrue` — if the required environment variable is not set, the test is **skipped** (shown as ignored), not failed. This is expected behavior.

## Features

- Objective-C
    -  [x] Better encoding parsers
    -  [x] Class modeling
    -  [x] Enhanced method signature propagation
        -  [x] Extended method signature types using MRO
        -  [x] Automatic selector-based parameter renaming
    -  [x] Automatic property tagging and annotation
    -  [x] NSBlock Analysis
- Swift
    -  [x] Small string analysis (arm64 and x86_64)
    -  [x] String literal XREF analysis
- Universal
    -  [ ] Improved DYLD shared cache loader

---

## Troubleshooting

**`GHIDRA_INSTALL_DIR` not found during build**
Make sure the variable was exported in the current shell, not just assigned without `export`.

**Analyzers not showing up in Ghidra**
Check that the `GhidraApple` folder exists under `$GHIDRA_INSTALL_DIR/Ghidra/Extensions/` and that Ghidra was restarted after installation.

**Java version error**
Confirm with `java -version` that you're running Temurin 21. Other distributions (Oracle JDK, GraalVM) may cause incompatibilities.

**Build fails with Gradle error**
Always use the wrapper `./gradlew` — never a globally installed Gradle — to ensure version 8.10 is used.
