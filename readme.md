# GhidraApple — Development Setup

Complete guide to set up the GhidraApple extension development environment.

---

## Requirements

| Tool | Version | Notes |
|---|---|---|
| Java (Temurin) | 21 | Required — other distributions may cause issues |
| Gradle | 8.10 | Via Gradle Wrapper (`./gradlew`) |
| Ghidra | 12.0.3 | |
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
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC
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
dist/ghidra_12.0.3_PUBLIC_<date>_GhidraApple.zip
```

---

## 4. Installing in Ghidra

### Option A — via UI (recommended for first install)

1. Open Ghidra
2. `File > Install Extensions`
3. Click `+` and select the `.zip` from the `dist/` folder
4. Restart Ghidra

### Option B — direct copy (faster for iterating)

```bash
# Remove previous version
rm -rf $GHIDRA_INSTALL_DIR/Ghidra/Extensions/GhidraApple

# Copy the build output directly, no .zip needed
cp -r build/extension $GHIDRA_INSTALL_DIR/Ghidra/Extensions/GhidraApple
```

---

## 5. IntelliJ IDEA Setup

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

## Troubleshooting

**`GHIDRA_INSTALL_DIR` not found during build**
Make sure the variable was exported in the current shell, not just assigned without `export`.

**Analyzers not showing up in Ghidra**
Check that the `GhidraApple` folder exists under `$GHIDRA_INSTALL_DIR/Ghidra/Extensions/` and that Ghidra was restarted after installation.

**Java version error**
Confirm with `java -version` that you're running Temurin 21. Other distributions (Oracle JDK, GraalVM) may cause incompatibilities.

**Build fails with Gradle error**
Always use the wrapper `./gradlew` — never a globally installed Gradle — to ensure version 8.10 is used.