# Agent Guidelines for HO ArkTS Project

This is a HO native application built with ArkTS and ArkUI framework (API Level 20).

## Build Commands

```bash
# Build HAP package
hvigorw assembleHap

# Build specific module
hvigorw --mode module -p module=entry@default -p product=default assembleHap

# Clean build artifacts
hvigorw clean

# Run all tests
hvigorw test

# Run local unit tests (no device required)
hvigorw testLocalUnit

# Run instrumented tests (requires device/emulator)
hvigorw testOhos

# Install to connected device
hvigorw install

# Build in release mode (with obfuscation)
hvigorw assembleHap --mode release
```

## Running Single Tests

For local unit tests, modify the test file temporarily or use filter parameters:
```bash
# Run specific test suite (if supported by hypium configuration)
hvigorw testLocalUnit --filter=TestSuiteName
```

Note: Hypium framework filtering may require checking hvigor configuration. Alternative: temporarily comment out other test suites.

## Linting

```bash
# Run ESLint on ArkTS files
# Check code-linter.json5 for configuration
# Lints **/*.ets files, ignores test/ohosTest/build directories
```

## Code Style Guidelines

### Imports
- Group imports by kit/namespace, use `@kit.*` for APIs
- Common imports:
  ```typescript
  import { UIAbility, Want, AbilityConstant, common } from '@kit.AbilityKit';
  import { hilog } from '@kit.PerformanceKit';
  import { window } from '@kit.ArkUI';
  import { util } from '@kit.ArkTS';
  import { abilityConnectionManager } from '@kit.DistributedServiceKit';
  ```

### Naming Conventions
- **Classes:** PascalCase (e.g., `EntryAbility`, `CustomDialog01`)
- **Components/Structs:** PascalCase (e.g., `Index`, `MyComponent`)
- **Methods:** camelCase (e.g., `onCreate`, `buildSessionManagementSection`)
- **Variables:** camelCase (e.g., `currentSessionId`, `messageToSend`)
- **Constants:** UPPER_SNAKE_CASE (e.g., `DOMAIN = 0x0000`)
- **Decorators:** `@Entry`, `@Component`, `@CustomDialog`, `@Builder`, `@State`, `@Prop`

### Types and Type Annotations
- Always use explicit type annotations for function returns and parameters
- Common types: `: void`, `: string`, `: number`, `: boolean`, `: Promise<void>`, `: Object`, `: ESObject`
- Use array syntax: `Array<string>`, `Map<string, boolean>`
- Callback types: `((callbackInfo: Object) => void) | null`

### Error Handling
- Always wrap API calls in try-catch blocks
- Log errors with `hilog.error()` or `hilog.warn()`
- Use `JSON.stringify(err)` for error serialization
- Example:
  ```typescript
  try {
    abilityConnectionManager.connect(this.currentSessionId);
  } catch (error) {
    hilog.error(DOMAIN, 'testTag', 'Failed: %{public}s', JSON.stringify(error));
  }
  ```

### ArkUI Component Structure
- Use `@Entry` and `@Component` decorators for pages
- Use `@CustomDialog` for dialogs
- Use `@Builder` for reusable UI sections
- State management with `@State` decorator
- Example:
  ```typescript
  @Entry
  @Component
  struct MyComponent {
    @State message: string = 'Hello';
    
    build() {
      Column() {
        Text(this.message)
      }
    }
  }
  ```

### Resource References
- Use `$r()` syntax in code: `$r('string.app_name')`, `$r('media.icon')`
- Use `$type:name` in JSON: `"$string:EntryAbility_label"`

### Testing Guidelines
- Framework: `@ohos/hypium` (1.0.24), `@ohos/hamock` (1.0.0)
- Test files: `*.test.ets` in `entry/src/test/` (local) or `entry/src/ohosTest/` (instrumented)
- Test structure:
  ```typescript
  import { describe, it, expect, beforeAll, beforeEach, afterEach, afterAll } from '@ohos/hypium';
  
  export default function testSuite() {
    describe('testSuite', () => {
      beforeAll(() => { /* setup once */ });
      beforeEach(() => { /* setup per test */ });
      afterEach(() => { /* cleanup per test */ });
      afterAll(() => { /* cleanup once */ });
      
      it('testName', 0, () => {
        expect(value).assertEqual(expected);
      });
    });
  }
  ```

### Formatting
- Indentation: 2 spaces
- Max line length: ~2000 chars (truncated by Read tool)
- Chinese comments are acceptable in this codebase

### Security
- Cryptography APIs must be secure (AES, hash, RSA, etc.)
- Security rules enforced via ESLint: `@security/no-unsafe-*`

### Important Notes
- This is a Stage model app (not FA model)
- Package manager: OHPM (not npm/yarn)
- Signing is mandatory for all builds
- Resource files in `entry/src/main/resources/`
- Module manifest in `entry/src/main/module.json5`
