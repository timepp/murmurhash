import * as assert from 'jsr:@std/assert'
import * as mmh3 from './murmurhash.ts'

const data = [
    {
        text: 'http://en.wikipedia.org/wiki/MurmurHash',
        seed: 0,
        hash_x86_32: 0x4cfd1e8an,
        hash_x86_128: 0xd297dc9fad5b8f84f8264f326908431an,
        hash_x64_128: 0x408b5d5478a695f2b843c4e74b27f5d7n
    }
]

Deno.test('test', () => {
    for (const d of data) {
        const h1 = mmh3.murmurHash3_x64_128(d.text, d.seed)
        console.log(h1.toString(16))
        assert.assertEquals(h1, d.hash_x64_128)

        const h2 = mmh3.murmurHash3_x86_32(d.text, d.seed)
        console.log(h2.toString(16))
        assert.assertEquals(h2, d.hash_x86_32)

        const h3 = mmh3.murmurHash3_x86_128(d.text, d.seed)
        console.log(h3.toString(16))
        assert.assertEquals(h3, d.hash_x86_128)
    }
})
