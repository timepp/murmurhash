function add64(a: bigint, b: bigint): bigint {
    return BigInt.asUintN(64, a + b);
}

function add32(a: bigint, b: bigint): bigint {
    return BigInt.asUintN(32, a + b);
}

function mul64(a: bigint, b: bigint): bigint {
    return BigInt.asUintN(64, a * b);
}

function mul32(a: bigint, b: bigint): bigint {
    return BigInt.asUintN(32, a * b);
}

function rotl64(x: bigint, r: number): bigint {
    return BigInt.asUintN(64, (x << BigInt(r)) | (x >> BigInt(64 - r)));
}

function rotl32(x: bigint, r: number): bigint {
    return BigInt.asUintN(32, (x << BigInt(r)) | (x >> BigInt(32 - r)));
}

function getBlock64(keyBytes: Uint8Array, i: number): bigint {
    return BigInt.asUintN(64, BigInt(keyBytes[i * 8]) |
        (BigInt(keyBytes[i * 8 + 1]) << 8n) |
        (BigInt(keyBytes[i * 8 + 2]) << 16n) |
        (BigInt(keyBytes[i * 8 + 3]) << 24n) |
        (BigInt(keyBytes[i * 8 + 4]) << 32n) |
        (BigInt(keyBytes[i * 8 + 5]) << 40n) |
        (BigInt(keyBytes[i * 8 + 6]) << 48n) |
        (BigInt(keyBytes[i * 8 + 7]) << 56n));
}

function getBlock32(keyBytes: Uint8Array, i: number): bigint {
    return BigInt.asUintN(32, BigInt(keyBytes[i * 4]) |
        (BigInt(keyBytes[i * 4 + 1]) << 8n) |
        (BigInt(keyBytes[i * 4 + 2]) << 16n) |
        (BigInt(keyBytes[i * 4 + 3]) << 24n));
}

function fmix64(k: bigint): bigint {
    k ^= k >> 33n;
    k = mul64(k, 0xff51afd7ed558ccdn);
    k ^= k >> 33n;
    k = mul64(k, 0xc4ceb9fe1a85ec53n);
    k ^= k >> 33n;
    return k;
}

function fmix32(k: bigint): bigint {
    k ^= k >> 16n;
    k = mul32(k, 0x85ebca6bn);
    k ^= k >> 13n;
    k = mul32(k, 0xc2b2ae35n);
    k ^= k >> 16n;
    return k;
}

/**
 * Generate murmurhash3 x64 128-bit hash
 * @param key original data
 * @param seed 
 * @returns the hash value as a BigInt
 */
export function murmurHash3_x64_128(key: string, seed: number = 0) : bigint{
    let h1 = BigInt(seed);
    let h2 = BigInt(seed);

    const keyBytes = new TextEncoder().encode(key);
    const length = keyBytes.length;
    const blocks = Math.floor(length / 16);

    const c1 = 0x87c37b91114253d5n;
    const c2 = 0x4cf5ad432745937fn;

    // Body
    for (let i = 0; i < blocks; i++) {
        let k1 = getBlock64(keyBytes, i * 2);
        let k2 = getBlock64(keyBytes, i * 2 + 1);

        k1 = mul64(k1, c1); k1 = rotl64(k1, 31); k1 = mul64(k1, c2); h1 ^= k1;
        h1 = rotl64(h1, 27); h1 = add64(h1, h2); h1 = add64(mul64(h1, 5n), 0x52dce729n);

        k2 = mul64(k2, c2); k2 = rotl64(k2, 33); k2 = mul64(k2, c1); h2 ^= k2;
        h2 = rotl64(h2, 31); h2 = add64(h2, h1); h2 = add64(mul64(h2, 5n), 0x38495ab5n);
    }

    // Tail
    let k1 = 0n;
    let k2 = 0n;
    const tail = [...keyBytes.slice(blocks * 16)].map(x => BigInt(x));

    switch (tail.length) {
        case 15: k2 ^= tail[14] << 48n; // fallthrough
        case 14: k2 ^= tail[13] << 40n; // fallthrough
        case 13: k2 ^= tail[12] << 32n; // fallthrough
        case 12: k2 ^= tail[11] << 24n; // fallthrough
        case 11: k2 ^= tail[10] << 16n; // fallthrough
        case 10: k2 ^= tail[9]  << 8n;  // fallthrough
        case 9:  k2 ^= tail[8]  << 0n; k2 = mul64(k2, c2); k2 = rotl64(k2, 33); k2 = mul64(k2, c1); h2 ^= k2; // fallthrough
        case 8:  k1 ^= tail[7]  << 56n; // fallthrough
        case 7:  k1 ^= tail[6]  << 48n; // fallthrough
        case 6:  k1 ^= tail[5]  << 40n; // fallthrough
        case 5:  k1 ^= tail[4]  << 32n; // fallthrough
        case 4:  k1 ^= tail[3]  << 24n; // fallthrough
        case 3:  k1 ^= tail[2]  << 16n; // fallthrough
        case 2:  k1 ^= tail[1]  << 8n;  // fallthrough
        case 1:  k1 ^= tail[0]  << 0n; k1 = mul64(k1, c1); k1 = rotl64(k1, 31); k1 = mul64(k1, c2); h1 ^= k1;
    }

    // Finalization
    h1 ^= BigInt(length);
    h2 ^= BigInt(length);

    h1 = add64(h1, h2);
    h2 = add64(h2, h1);

    h1 = fmix64(h1);
    h2 = fmix64(h2);

    h1 = add64(h1, h2);
    h2 = add64(h2, h1);

    return h1 << 64n | h2;
}

/**
 * Generate murmurhash3 x86 128-bit hash
 * @param key original data
 * @param seed 
 * @returns the hash value as a BigInt
 */
export function murmurHash3_x86_128(key: string, seed: number = 0): bigint {
    let h1 = BigInt(seed);
    let h2 = BigInt(seed);
    let h3 = BigInt(seed);
    let h4 = BigInt(seed);

    const keyBytes = new TextEncoder().encode(key);
    const length = keyBytes.length;
    const blocks = Math.floor(length / 16);
  
    const c1 = 0x239b961bn;
    const c2 = 0xab0e9789n;
    const c3 = 0x38b34ae5n;
    const c4 = 0xa1e38b93n;
  
    // body
    for (let i = 0; i < blocks; i++) {
        let k1 = getBlock32(keyBytes, i * 4);
        let k2 = getBlock32(keyBytes, i * 4 + 1);
        let k3 = getBlock32(keyBytes, i * 4 + 2);
        let k4 = getBlock32(keyBytes, i * 4 + 3);

        k1 = mul32(k1, c1); k1 = rotl32(k1, 15); k1 = mul32(k1, c2); h1 ^= k1;
        h1 = rotl32(h1, 19); h1 = add32(h1, h2); h1 = add32(mul32(h1, 5n), 0x561ccd1bn);

        k2 = mul32(k2, c2); k2 = rotl32(k2, 16); k2 = mul32(k2, c3); h2 ^= k2;
        h2 = rotl32(h2, 17); h2 = add32(h2, h3); h2 = add32(mul32(h2, 5n), 0x0bcaa747n);

        k3 = mul32(k3, c3); k3 = rotl32(k3, 17); k3 = mul32(k3, c4); h3 ^= k3;
        h3 = rotl32(h3, 15); h3 = add32(h3, h4); h3 = add32(mul32(h3, 5n), 0x96cd1c35n);

        k4 = mul32(k4, c4); k4 = rotl32(k4, 18); k4 = mul32(k4, c1); h4 ^= k4;
        h4 = rotl32(h4, 13); h4 = add32(h4, h1); h4 = add32(mul32(h4, 5n), 0x32ac3b17n);
    }

    const tail = [...keyBytes.slice(blocks * 16)].map(x => BigInt(x));
  
    let k1 = 0n;
    let k2 = 0n;
    let k3 = 0n;
    let k4 = 0n;

    switch (tail.length) {
        case 15: k4 ^= tail[14] << 16n; // fallthrough
        case 14: k4 ^= tail[13] << 8n;  // fallthrough
        case 13: k4 ^= tail[12] << 0n;  k4 = mul32(k4, c4); k4 = rotl32(k4, 18); k4 = mul32(k4, c1); h4 ^= k4; // fallthrough
        case 12: k3 ^= tail[11] << 24n; // fallthrough
        case 11: k3 ^= tail[10] << 16n; // fallthrough
        case 10: k3 ^= tail[9]  << 8n;  // fallthrough
        case 9:  k3 ^= tail[8]  << 0n;  k3 = mul32(k3, c3); k3 = rotl32(k3, 17); k3 = mul32(k3, c4); h3 ^= k3; // fallthrough
        case 8:  k2 ^= tail[7]  << 24n; // fallthrough
        case 7:  k2 ^= tail[6]  << 16n; // fallthrough
        case 6:  k2 ^= tail[5]  << 8n;  // fallthrough
        case 5:  k2 ^= tail[4]  << 0n;  k2 = mul32(k2, c2); k2 = rotl32(k2, 16); k2 = mul32(k2, c3); h2 ^= k2; // fallthrough
        case 4:  k1 ^= tail[3]  << 24n; // fallthrough
        case 3:  k1 ^= tail[2]  << 16n; // fallthrough
        case 2:  k1 ^= tail[1]  << 8n;  // fallthrough
        case 1:  k1 ^= tail[0]  << 0n;  k1 = mul32(k1, c1); k1 = rotl32(k1, 15); k1 = mul32(k1, c2); h1 ^= k1;
    }

    // finalization
    h1 ^= BigInt(length);
    h2 ^= BigInt(length);
    h3 ^= BigInt(length);
    h4 ^= BigInt(length);
  
    h1 = add32(h1, h2); h1 = add32(h1, h3); h1 = add32(h1, h4);
    h2 = add32(h2, h1); h3 = add32(h3, h1); h4 = add32(h4, h1);
  
    h1 = fmix32(h1);
    h2 = fmix32(h2);
    h3 = fmix32(h3);
    h4 = fmix32(h4);

    h1 = add32(h1, h2); h1 = add32(h1, h3); h1 = add32(h1, h4);
    h2 = add32(h2, h1); h3 = add32(h3, h1); h4 = add32(h4, h1);

    return h1 << 96n | h2 << 64n | h3 << 32n | h4;
}

/** 
 * Generate murmurhash3 x86 32-bit hash
 * @param key original data
 * @param seed 
 * @returns the hash value as a BigInt
*/
export function murmurHash3_x86_32(key: string, seed: number = 0): bigint {
    let h1 = BigInt(seed);

    const keyBytes = new TextEncoder().encode(key);
    const length = keyBytes.length;
    const blocks = Math.floor(length / 4);

    const c1 = 0xcc9e2d51n;
    const c2 = 0x1b873593n;

    // body
    for (let i = 0; i < blocks; i++) {
        let k1 = getBlock32(keyBytes, i);
        k1 = mul32(k1, c1); k1 = rotl32(k1, 15); k1 = mul32(k1, c2); h1 ^= k1;
        h1 = rotl32(h1, 13); h1 = add32(mul32(h1, 5n), 0xe6546b64n);
    }

    const tail = [...keyBytes.slice(blocks * 4)].map(x => BigInt(x));

    let k1 = 0n;

    switch (tail.length) {
        case 3: k1 ^= tail[2] << 16n; // fallthrough
        case 2: k1 ^= tail[1] << 8n;  // fallthrough
        case 1: k1 ^= tail[0] << 0n;  k1 = mul32(k1, c1); k1 = rotl32(k1, 15); k1 = mul32(k1, c2); h1 ^= k1;
    }

    // finalization
    h1 ^= BigInt(length);
    h1 = fmix32(h1);

    return h1;
}