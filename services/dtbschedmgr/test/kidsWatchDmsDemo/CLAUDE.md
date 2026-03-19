# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **(OpenHarmony) native application** built with ArkTS (Ark TypeScript) and the ArkUI framework. The app targets 6.0.0 (API Level 20) and uses the modern Stage model architecture.

**Key Technologies:**
- **Language:** ArkTS (TypeScript with specific decorators and APIs)
- **UI Framework:** ArkUI
- **Build System:** Hvigor (build tool, Gradle-inspired)
- **Package Manager:** OHPM (OpenHarmony Package Manager)
- **IDE:** DevEco Studio (official IDE)

## Architecture

### Stage Model (Modern Architecture)

This project uses the **Stage model**, which is the current application architecture (not the legacy FA model).

**Key Components:**

1. **EntryAbility** (`entry/src/main/ets/entryability/EntryAbility.ets`):
   - Main application entry point extending `UIAbility`
   - Manages app lifecycle: `onCreate()`, `onDestroy()`, `onForeground()`, `onBackground()`
   - Window management: `onWindowStageCreate()`, `onWindowStageDestroy()`
   - Loads the main page: `pages/Index`
   - Sets color mode configuration

2. **EntryBackupAbility** (`entry/src/main/ets/entrybackupability/EntryBackupAbility.ets`):
   - Extension ability for app backup/restore
   - Extends `BackupExtensionAbility`
   - Implements `onBackup()` and `onRestore()` methods

3. **Pages** (`entry/src/main/ets/pages/`):
   - Declarative UI using ArkUI framework
   - Decorated with `@Entry` (page entry point) and `@Component` (component definition)
   - State management with `@State` decorator for reactive updates
   - The main Index page demonstrates `abilityConnectionManager.createAbilityConnectionSession()` API for creating connection sessions with peer services

### Module Configuration

**Module Manifest** (`entry/src/main/module.json5`):
- Module type: `entry` (main application module)
- Device types: phone, wearable
- Main element: EntryAbility
- Pages defined in `main_pages.json` profile
- Abilities and extension abilities registered here

### Resource Organization

Resources are organized under `entry/src/main/resources/`:

- **base/**: Default resources (colors, strings, floats, media, profiles)
- **dark/**: Dark mode theme resources
- **rawfile/**: Raw asset files

Resource references use special syntax: `$string:name`, `$color:name`, `$media:name`

## Common Commands

### Building

```bash
# Build the project (HAP file)
hvigorw --mode module -p module=entry@default -p product=default assembleHap

# Clean build artifacts
hvigorw clean

# Build in release mode (with obfuscation)
hvigorw assembleHap --mode release
```

### Testing

```bash
# Run all tests
hvigorw test

# Run local unit tests (no device required)
hvigorw testLocalUnit

# Run instrumented tests (requires device/emulator)
hvigorw testOhos
```

### Installation

```bash
# Install to connected device
hvigorw install
```

## Development Workflow

### Project Structure

- **AppScope/**: Application-level configuration (app.json5, app resources)
- **entry/**: Main entry module
  - **src/main/ets/**: ArkTS source code
  - **src/main/resources/**: Module resources
  - **src/test/**: Local unit tests (run without device)
  - **src/ohosTest/**: Instrumented tests (run on device/emulator)
  - **build-profile.json5**: Module build configuration
  - **obfuscation-rules.txt**: Code obfuscation rules for release builds
- **hvigor/**: Hvigor build tool configuration
- **oh_modules/**: OHPM dependencies (like node_modules)

### Key Configuration Files

| File | Purpose |
|------|---------|
| `build-profile.json5` | Project-level build config, signing, SDK versions |
| `entry/build-profile.json5` | Module build config, obfuscation settings |
| `AppScope/app.json5` | App metadata (bundle name, version, icon) |
| `entry/src/main/module.json5` | Module manifest (abilities, permissions, pages) |
| `hvigor/hvigor-config.json5` | Build tool performance and execution settings |
| `oh-package.json5` | Project dependencies |
| `code-linter.json5` | ESLint configuration for ArkTS |

### Code Quality

- **ESLint** configured for ArkTS files (`**/*.ets`)
- Rule sets: `@performance/recommended`, `@typescript-eslint/recommended`
- Security rules enabled for cryptography (AES, hash, RSA, etc.)
- Linter ignores: test files, dependencies, build outputs

### Testing

- **Framework:** `@ohos/hypium` (1.0.24)
- **Mocking:** `@ohos/hamock` (1.0.0)
- Test patterns:
  - `describe()`: Test suite definition
  - `it()`: Test case definition
  - `expect()`: Assertion methods
  - Lifecycle hooks: `beforeAll()`, `beforeEach()`, `afterEach()`, `afterAll()`

### Code Obfuscation

- Enabled for release builds
- Rules defined in `entry/obfuscation-rules.txt`
- Obfuscates: properties, top-level names, filenames, exports

### Signing

- Signing is mandatory for all builds (including debug)
- Certificates and profiles stored in user's `.ohos/config/` directory
- Debug signing configured in `build-profile.json5`
- Signing algorithm: SHA256withECDSA

## ArkUI/ArkTS Specifics

### Decorators

- `@Entry`: Marks a component as a page entry point
- `@Component`: Defines a UI component
- `@CustomDialog`: Defines a custom dialog
- `@State`: Reactive state management (triggers UI updates when changed)

### Common Imports

```typescript
// Ability lifecycle and context
import { UIAbility, Want, AbilityConstant, ConfigurationConstant } from '@kit.AbilityKit';
import { common } from '@kit.AbilityKit';

// Distributed services (connection management)
import { abilityConnectionManager } from '@kit.DistributedServiceKit';

// Window management
import { window } from '@kit.ArkUI';

// Logging
import { hilog } from '@kit.PerformanceAnalysisKit';
```

### UI Component Structure

```typescript
@Component
struct MyComponent {
  @State message: string = 'Hello';

  build() {
    Column() {
      Text(this.message)
      Button('Click')
        .onClick(() => {
          // Handle click
        })
    }
  }
}
```

### Resource References

```typescript
// In code: use $r() syntax
Text($r('string.app_name'))
Image($r('media.icon'))

// In JSON: use $type:name syntax
"$string:EntryAbility_label"
"$media:layered_image"
```

## Build Outputs

- Build outputs go to `entry/build/` directory
- Main artifact: HAP (Ability Package) file
- Debug builds: Full debugging support, no obfuscation
- Release builds: Code obfuscation enabled

## Application Purpose

This is a test/demo application exploring the `abilityConnectionManager` API, which is used for creating connection sessions between abilities. The app provides a simple UI to test connection session creation with peer services, demonstrating distributed service capabilities.

## Important Notes

1. **Not a typical web project** - This is a native mobile application
2. **ArkTS ≈ TypeScript** - But with specific decorators and APIs
3. **Stage model** - Modern architecture (not FA model)
4. **OHPM** - Package manager (not npm/yarn)
5. **DevEco Studio** - Primary IDE (though VS Code is possible)
6. **Signing** - Mandatory even for development builds
7. **Testing** - Requires specific frameworks (hypium, hamock)
