#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>

int count = 0;

int main(int argc, char const *argv[])
{
    for (int64_t i = 10000000000000001LL; i >= 0; --i) {
        int64_t sqrted = sqrt(i);
        if (i >= sqrted * sqrted && i < (sqrted + 1) * (sqrted + 1)) {
            continue;
        }
        printf("%lld\n", i);
        count++;
        if (count >= 150) {
            return 0;
        }
    }
    return 0;
}
