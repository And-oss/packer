# Advanced ELF Packer and Obfuscator

A sophisticated tool for packing, obfuscating, and protecting ELF binaries. Provides multi-layered protection against reverse engineering and analysis tools like IDA Pro.

## Features

- UPX-like Packing with PCK Headers
- String Obfuscation
  - Basic string encryption (simple XOR)
  - Advanced multi-layered string encryption
- Section Encryption
- Memory Protection
- Code Virtualization
- Anti-Debugging
- NOP Injection
- Full Protection Mode

## Building

```bash
g++ packer.cpp src/Encryption.cpp -o packer -std=c++17 -ldl -Isrc/header
```

## Usage

Basic usage pattern:

```bash
./packer -f <filename> [options]
```

### Command-line Options

```
  -f <filename>   Specify ELF file to modify
  -ni             Inject NOPs into .text section
  -s              Encrypt strings in .rodata
  -as             Advanced string obfuscation (IDA-resistant)
  -k <key>        Set XOR key for string encryption (default: 0xAA)
  -k1 <key>       Set first key for advanced string obfuscation
  -k2 <key>       Set second key for advanced string obfuscation
  -addr <address> Set address to inject NOPs (in hexadecimal format)
  -end            Patch NOPs at the end of .text section instead of a specific address
  -n <num>        Set number of NOPs to inject (default: 10)
  -h              Show this help message
  -es             Encrypt section
  -t              section's name or some text
  -pack           Pack the executable (UPX-like functionality with PCK format)
  -unpack         Unpack a previously packed executable
  -mem            Apply memory obfuscation techniques
  -vm             Apply code virtualization (strongest protection against IDA)
  -anti-dbg       Add anti-debugging protection
  -full           Apply full protection (all techniques combined)
  -check          Check if a file has PCK protection
```

## Examples

### Basic String Encryption

```bash
./packer -f myprogram -s -k 0x42
```

This will encrypt all strings in the `.rodata` section with the key `0x42`.

### Advanced String Obfuscation (IDA-resistant)

```bash
./packer -f myprogram -as -k1 0xBB -k2 0xCC
```

This applies multi-layered encryption to strings, making them extremely difficult to recover statically.

### PCK Format Packing (Maximum IDA Protection)

```bash
./packer -f myprogram -pack
```

Compresses and encrypts the executable with our proprietary PCK format, adding a runtime unpacker that completely prevents IDA from analyzing the code.

### Verify PCK Protection

```bash
./packer -f myprogram.packed -check
```

Checks if a file has been protected with the PCK format.

### Memory Protection

```bash
./packer -f myprogram -mem
```

Adds runtime memory protection to hide sensitive data from memory scanners.

### Code Virtualization

```bash
./packer -f myprogram -vm
```

Converts portions of native code to a custom bytecode that runs in a virtual machine, extremely effective against disassemblers.

### Full Protection

```bash
./packer -f myprogram -full
```

Applies all protection techniques in an optimal sequence for maximum security, including PCK headers.

## Protecting Critical Sections

To encrypt a specific section:

```bash
./packer -f myprogram -es -t .data -k 0xFF
```

## PCK Format Specification

The PCK format is our proprietary packing format that is specifically designed to defeat IDA Pro:

1. **PCK Header Signature**: Each protected file includes a "PCK" signature that identifies it as protected
2. **Multi-Layer Encryption**: Uses multiple encryption layers for each section (XOR, bit rotation, byte swapping)
3. **Deceptive Code**: Fills original sections with valid-looking but nonsensical code patterns that crash decompilers
4. **Anti-Analysis Mechanisms**: Detects and prevents static and dynamic analysis(in dev)
5. **Self-Modifying Unpacker**: Runtime unpacker modifies itself during execution(in dev)

## Anti-IDA Features(in dev)

This packer implements multiple techniques that specifically target and defeat IDA Pro's analysis capabilities:

1. **Multi-layered string encryption**: Uses multiple transformations to prevent automatic recovery
2. **Code virtualization**: Custom bytecode execution prevents accurate disassembly
3. **Garbage code generation**: Inserts misleading code patterns that break IDA's analysis
4. **Memory obfuscation**: Prevents memory dumps and analysis
5. **Opaque predicates**: Uses complex logic constructs that cannot be simplified statically
6. **Self-modifying code**: Changes itself at runtime to defeat static analysis
7. **Anti-debugging**: Detects and prevents debugging sessions
8. **PCK headers**: Signed format that identifies protected files and creates custom sections (.PCK and .unpacker)

## Limitations

- Some protections require sufficient privileges to run properly
- Heavily obfuscated executables may run slower than the original
- For maximum protection, combine multiple techniques
- PCK protection is designed to be permanent - once packed, a file cannot be unpacked while preserving the exact original code

## Warning

This tool is designed for legitimate software protection purposes. Use responsibly and legally.