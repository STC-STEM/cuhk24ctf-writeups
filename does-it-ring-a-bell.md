## Does it ring a bell?

### Challenge description:

Upon opening the excel file provided, we noticed a hidden sheet, `CiphererFlag`.

- The sheet take in a 31-character string and perform some checks on the string
- The string is actually the ROT47-encrypted flag
- There is a 7 rows x 31 column table, which updates as we change the encrypted flag (in particular each column shows the binary representation of each character)


Our goal is very clear: we have to find a correct flag which satisifies all 40 checks, namely:


1. The bottom row include 31 checks, each corresponding to a letter of the flag. Mathematically, the check of the `n`th character (note that n is a 0-based index) can be expressed as

```
(bits[1] * 1 + bits[2] * 2 + bits[3] * 3 + ... + bit[7] * 7) * (n + 1) == A_GIVEN_NUMBER
```

here `bits[0]` denote the most significant bit (MSB) and `bit[7]` denote the least significant bit of the of the ascii code of the  encrypted character

2. The side column include 7 checks. Similar to the bottom row check, it also calculate the weighted sum of the `i`th bit of all character, with the weight being `(n+1)` for the `n`th character (again n is a 0-based index). It can be expressed as

```
_0th_char_bits[i] * 1 + _1st_char_bit[i] * 2 + ...
    + _30th_char_bit[i] * 31 == A_GIVEN_NUMBER
```

3. The 'corner check' ensures that the 'sum of all weighted sums' is equal to a certain value. Since we already know the value of each individual weighted sum, this check is essentially useless.

4. There is another check performed on the 0th character

5. From the challenge description we know that the flag format is `cuhk24ctf{[a-zA-Z0-9_]+}`

```
_0th_char_bits[1] + _0th_char_bits[5] + _0th_char_bits[7] == 3
```

which implies that the encrypted first character (index 0) must has the binary representation `0x01???1?1`

### Solving

The challenge description directed us to another challenge that appeared in HKCERT 2021, in which the author present a solution using the **Z3 Theorem Solver**. However, ~~I don't know how to use z3~~ this challenge is rather simple and I used a solve script instead.

#### Finding the ROT cipher
1. The row check is not unique. Instead, it gives us 1-5 possible value of each of the 31 characters. In particular, the encrypted value of the first character must be one of the following:

```
enc[0] = & (38)
enc[0] = ) (41)
enc[0] = E (69)
enc[0] = \ (92)
enc[0] = q (113)
```

From condition (4) we know that the encrypted value must be `E`. Compare this to the known flag format `cuhk24ctf{...}`, we see that ROT64 is used for the encryption.

#### Prelimary guess

We run our prelimary solve script

```[python]
def rot64enc(s):
    return 33 + ((s - 33 + 64) % 94)

def rot64dec(s):
    return ((s - 33 + 94 + 94 - 64) % 94) + 33

def bit_op(row, col, flag_chr):
    # 1st row (row=0): RSHIFT by 6
    # 7th row (row=6): RSHIFT by 0
    return (flag_chr >> (6 - row)) & 1

flag_chrs = ascii_letters + digits + "_{}"

col_weighted_sum = [
    # First 8 row (15-22) of L, M, N, O
    13, 44, 33, 68,  # 15
    60, 66, 91, 120,
    45, 200, 99, 228,
    117, 112, 225, 64,
    204, 144, 190, 240,  # 19
    336, 176, 414, 96,
    200, 494, 405, 364,
    551, 390, 806  # 22
]

options = list(["" for _ in range(len(col_weighted_sum))])
for col in range(len(col_weighted_sum)):
    print(f"\nFor flag[{col}], we need weight={col_weighted_sum[col]}:")
    for rotted in range(33, 127):
        f = rot64dec(rotted)
        weighted = sum([bit_op(row, col, rotted) * (row + 1) for row in range(7)]) * (col + 1)
        if weighted == col_weighted_sum[col] and chr(f) in flag_chrs:
            print(f"enc[{col}] = {chr(rotted)} ({rotted}) and flag[{col}]={chr(f)} ({f})")
            options[col] += chr(rotted)
```

The script gives the result in the following format

```
For flag[0], we need weight=13:
enc[0] = & (38) and flag[0]=D (68)
enc[0] = ) (41) and flag[0]=G (71)
enc[0] = E (69) and flag[0]=c (99)
enc[0] = \ (92) and flag[0]=z (122)
enc[0] = q (113) and flag[0]=1 (49)
```

In particular, we note these following possibilities
```
...
enc[13] = A (65) and flag[13]=_ (95)
...
enc[17] = A (65) and flag[17]=_ (95)
...
enc[21] = A (65) and flag[21]=_ (95)

enc[22] = - (45) and flag[22]=K (75)
enc[22] = 3 (51) and flag[22]=Q (81)
enc[22] = K (75) and flag[22]=i (105)
enc[22] = u (117) and flag[22]=5 (53)

enc[23] = P (80) and flag[23]=n (110) [as the only possibility]
enc[24] = A (65) and flag[24]=_ (95)
...
```

Assuming the underscores are at the correct position, and that `enc[22] == K`, our flag becomes `cuhk24ctf{???_???_???_in_?????}`

#### Final brute force

Because the solution of the above conditions (and assumptions) are not necessarily unique, we should perform a brute-force to search all the possible solutions under these assumption.

(my brain were too tired to use recursion)
```

flag_len = 31

def is_match(_flag_buf):
    row_weighted_sum = [
        381, 185, 272,
        120, 203, 219, 317]

    for row in range(7):
        if not sum([bit_op(row, col, _flag_buf[col]) * (col + 1) for col in range(flag_len)]) == row_weighted_sum[row]:
            return False
    return True

# A search going through the permutation of all 14 unknown characters
for flag_buf in permute(...):
    if is_match(flag_buf):
        print(f"Match found!!!!! flag={''.join([chr(rot64dec(c)) for c in flag_buf])}; enc={''.join([chr(c) for c in flag_buf])}")

```
Output:

```
Match found!!!!! flag=cuhk24ctf{VIr_AnH_ROT_in_etc31}; enc=EWJMrtEVH]8+TA#P*A416AKPAGVEsq_

Match found!!!!! flag=cuhk24ctf{V3r_An2_ROT_in_etcI1}; enc=EWJMrtEVH]8sTA#PrA416AKPAGVE+q_

Match found!!!!! flag=cuhk24ctf{rIr_And_ROT_in_etG31}; enc=EWJMrtEVH]T+TA#PFA416AKPAGV)sq_

Match found!!!!! flag=cuhk24ctf{reV_And_ROT_in_eXc31}; enc=EWJMrtEVH]TG8A#PFA416AKPAG:Esq_

Match found!!!!! flag=cuhk24ctf{r3V_An2_ROT_in_eXce1}; enc=EWJMrtEVH]Ts8A#PrA416AKPAG:EGq_
```

Only the last two result make sense. and `cuhk24ctf{reV_And_ROT_in_eXc31}` is the correct flag!
