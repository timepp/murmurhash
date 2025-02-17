# murmurHash typescript implementation

This is a typescript implementation of the murmurHash algorithm. The murmurHash algorithm is a non-cryptographic hash function suitable for general hash-based lookup. It was created by Austin Appleby in 2008. The algorithm is designed to generate a good distribution of hash values with a minimum of collisions. It is optimized for x86 processors, but it should work on any processor.

This implementation is based on the original C++ implementation by Austin Appleby. The original implementation can be found at github: https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp

## Usage

```typescript
    import * as mmh from 'jsr:@timepp/murmurhash'
    const hash = mmh.murmurHash3_x64_128('hello')
    console.log(hash.toString(16))
    // output: cbd8a7b341bd9b025b1e906a48ae1d19
```
