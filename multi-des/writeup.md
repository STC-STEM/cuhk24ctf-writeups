### MultiDES

`chal.py`

```
class MultipleDES:
    def __init__(self, key: bytes):
        self.key = key.hex().encode()

    def encrypt(self, message: bytes) -> bytes:
        ciphertext = message
        for i in range(0, len(self.key), 8):
            cipher = DES.new(self.key[i:i+8], DES.MODE_ECB)
            ciphertext = cipher.encrypt(ciphertext).hex().encode()
            print(f"i={i}; key={self.key[i:i+8]}; cipherLength={len(ciphertext)}")
        return ciphertext

def main():
    try:
        with open('flag.txt', 'rb') as f: m = f.read()
    except:
        # Do not submit. This is not the real flag.
        m = b'flag{this_is_a_test_flag______________________________}'
    m = pad(m, 8)

    key = os.urandom(32)
    cipher = MultipleDES(key)
    c = cipher.encrypt(m)
    with open('flag_test.txt.enc', 'wb') as f:
        f.write(c)


if __name__ == '__main__':
    main()

```

#### Idea
Normally, a cascaded encryption with 8 layers of DES would mean an effective key size of `(2^64)^8`, which is equvalent to a 512-bit key! Theoretically, it wouldn't be brute-forceable, but we could notice some flaws in the implementation.

1. The line `self.key = key.hex().encode()`

The key used is a 8-character hexadecimal string generated from 32-bit of random data. This makes the effective key size of each layer of encryption 32-bit. Hence we can simply try all the 8-character hexadecimal string, which can be done in a reasonable amount of time


2. `cipher.encrypt(ciphertext).hex().encode()`

The previous cipher text is converted to hexadecimal representation (of their ASCII code) before being encrypted again. This means that we can check if the key is correct by checking whenever the cleartext obtained is a hexadecimal string.

#### Brute force

To increase the brute force speed, I chose to write the program in C instead of python.

- For each of the iteration, the program take in the first 8 bytes of the ciphertext and attempt to to find a (hexadecimal) key which would decrypt the `ciphertext` into a hexadecimal string.
- In the last iteration, the program will seek for a key which would decrypt `ciphertext[0:8]` into `cuhk24ct`

```[c]
// Using an implementation found on github
// https://github.com/dhuertas/DES/blob/master/des.c
// See the source file in the folder
uint64_t des(uint64_t input, uint64_t key, char mode) {
    // ...
}


// Nth byte, from left (most significant byte) to right (LSB)
#define NBYTE(l, n) ((unsigned char)((l >> (8*(7-n))) & 0xff))
#define NBYTEHEX(l, n) HEX[(NBYTE(l, n) >> 4) & 0xf], HEX[(NBYTE(l, n)) & 0xf]

// from left (most significant byte) to right (LSB); start from 1 to 8
#define NTHHEXCHAR(i, n) HEX[i >> 4*(8-n) & 0xf]
#define CUHK24CT 0x6375686b32346374

int main(int argc, const char * argv[]) {
    if (argc != 5) {
        printf("Usage: ./brute [8-byte hex string with 0x prefix] [startIndex] [endIndex] [logfile]\n");
        return 1;
    }

    const uint64_t input = strtoul(argv[1], NULL, 16);
    const uint32_t start = strtoul(argv[2], NULL, 10);
    const uint32_t end = strtoul(argv[3], NULL, 10);

    FILE *fptr = fopen(argv[4], "w");
    char HEX[] = "0123456789abcdef";

    for (uint32_t i = start; i < end; i++) {
        if (i % (16*16*16*16*16) == 0) {
            time_t t = time(NULL);
            struct tm curtime = *localtime(&t);

            fprintf(fptr, "[%d-%02d-%02d %02d:%02d:%02d] Index=%u; Progress=(%i / %i)\n", curtime.tm_year + 1900, curtime.tm_mon + 1, curtime.tm_mday, curtime.tm_hour, curtime.tm_min, curtime.tm_sec, i, i / (16*16*16*16*16), 16*16*16);
            fflush(fptr);
        }

        uint64_t test_key =
            (((uint64_t) NTHHEXCHAR(i, 1)) << 56) | (((uint64_t) NTHHEXCHAR(i, 2)) << 48) |
            (((uint64_t) NTHHEXCHAR(i, 3)) << 40) | (((uint64_t) NTHHEXCHAR(i, 4)) << 32) |
            (((uint64_t) NTHHEXCHAR(i, 5)) << 24) | (((uint64_t) NTHHEXCHAR(i, 6)) << 16) |
            (((uint64_t) NTHHEXCHAR(i, 7)) << 8) | (((uint64_t) NTHHEXCHAR(i, 8)));

        uint64_t out = des(input, test_key, 'd');

        /* For cracking nested encryptions */
        for (char j = 0; j < 8; j++) {
            if((NBYTE(out, j) < 'a' || NBYTE(out, j) > 'f') &&
                (NBYTE(out, j) < '0' || NBYTE(out, j) > '9')) {
                goto not_found;
                }

        /* For brute-forcing the first round of encryption */
        // if (out != CUHK24CT) {
        //     goto not_found;
        // }

        fprintf(fptr, "Found the clear text %llu; key used is 0x%c%c%c%c%c%c%c%c\n", out,
            NBYTE(test_key, 0),
            NBYTE(test_key, 1),
            NBYTE(test_key, 2),
            NBYTE(test_key, 3),
            NBYTE(test_key, 4),
            NBYTE(test_key, 5),
            NBYTE(test_key, 6),
            NBYTE(test_key, 7));
        not_found:;
    }

    fclose(fptr);
    exit(0);
}
```

and script to run 16 parallel instances
```
cipherText="0x3110d75d5887aa0f"
./brute ${cipherText} 0 268435456 out0.txt &
./brute ${cipherText} 268435456 536870912 out1.txt &
./brute ${cipherText} 536870912 805306368 out2.txt &
./brute ${cipherText} 805306368 1073741824 out3.txt &
./brute ${cipherText} 1073741824 1342177280 out4.txt &
./brute ${cipherText} 1342177280 1610612736 out5.txt &
./brute ${cipherText} 1610612736 1879048192 out6.txt &
./brute ${cipherText} 1879048192 2147483648 out7.txt &
./brute ${cipherText} 2147483648 2415919104 out8.txt &
./brute ${cipherText} 2415919104 2684354560 out9.txt &
./brute ${cipherText} 2684354560 2952790016 out10.txt &
./brute ${cipherText} 2952790016 3221225472 out11.txt &
./brute ${cipherText} 3221225472 3489660928 out12.txt &
./brute ${cipherText} 3489660928 3758096384 out13.txt &
./brute ${cipherText} 3758096384 4026531840 out14.txt &
./brute ${cipherText} 4026531840 4294967296 out15.txt
```

The output file looks something like this
```
[2024-10-13 09:24:46] Index=2730491904; Progress=(2604 / 4096)
[2024-10-13 09:24:49] Index=2731540480; Progress=(2605 / 4096)
Found the clear text 3990812023857504567; key used is 0xa2d288b2
Found the clear text 3990812023857504567; key used is 0xa2d288b3
Found the clear text 3990812023857504567; key used is 0xa2d288c2
Found the clear text 3990812023857504567; key used is 0xa2d288c3
...
[2024-10-13 09:24:53] Index=2732589056; Progress=(2606 / 4096)
```

There are multiple key which could successfully decrypt the first block of the ciphertext into the same result. Upon checking, I found that these key actually produce the same result for every block of the ciphertext (due to reasons that cannot be explained by my current knowledge in cryptography). In particular, the number of possible keys are always `2^n`: sometime it is 128, sometime 64 or less.

The brute-force program takes around 15 minutes to run. By repeating the brute-force program 8 times, the original flag can be found.

```[python]
_nthKeys = []
for i in range(16):
    found = 0
    with open(f'log_{iteration}th/out{i}.txt', 'r') as f:
        for line in f.readlines():
            if line.startswith("Found"):
                found += 1
                _nthKeys.append(line[-9:-1].encode())

    print(f'{found} keys found in log_{iteration}th/out{i}.txt')

with open(f"{iteration}th_cipher.txt.enc", 'r') as f:
    nthIterCipher = f.read()

# any key would work
cipher = DES.new(_nthKeys[0], DES.MODE_ECB)
for i in range(0, len(nthIterCipher), 8):
    print(cipher.decrypt(nthIterCipher[i:i + 8]))
```

Here are the keys used for encrypting the original file (`key[0]` is for the first iteration)
```[python]
keys = [b'ad6db4af', b'f5f9b0c2', b'93d7dafd', b'96a8fa67', b'f91d9d50', b'ec9f005d', b'a2d289b2']
```