# cpuminer-e2kv5-template
Template patch and build instructions (in Russian) to speed-up cpuminer on E2K architecture.

Алгоритм сборки:

0) Скомпилировать в ассемблер файлы sha2-e2k.c и scrypt-e2k.c (рекомендуется кросс-компилятор, на i5-2500K каждый запуск больше 10 секунд выходит):

```/opt/mcst/lcc-1.24.11.e2k-v4.4.19/bin/lcc -Wall -O4 -ffast -S -march=elbrus-v5 -fblock-size-limit=65535 sha2-e2k.c -o sha2-e2k.S```

```/opt/mcst/lcc-1.24.11.e2k-v4.4.19/bin/lcc -Wall -O4 -ffast -S -march=elbrus-v5 -fblock-size-limit=65535 scrypt-e2k.c -o scrypt-e2k.S```

1) ```git clone —recursive https://github.com/pooler/cpuminer.git```
2) ```cd cpuminer```
3) ```patch -p1 </path/to/e2k_miner.patch```
4) <скопировать в текущую директорию полученные на шаге 0 файлы>
5) ```./autogen.sh```
6) ```./configure CFLAGS="-O3 -ffast"```
7) ```make -j8```
8) ```./minerd --benchmark -a sha256d```

```[2021-08-05 20:49:51] thread 0: 2097152 hashes, 6839 khash/s``` (8СВ @ 1.55 ГГц)

9) ```./minerd --benchmark```

```[2021-08-05 20:44:39] thread 0: 4096 hashes, 8.53 khash/s``` (8СВ @ 1.55 ГГц)

P.S. Если отбросить модификации кода, то можно увидеть, почему Эльбрус часто кажется медленным в тестах. Под x86 написаны ассемблерные реализации под каждый набор SIMD расширений. Кросс-платформенный код с профилировкой на Эльбрусе где-то в 3 раза медленнее, чем новые реализации. Очевидно, в таких задачах на одном только компиляторе не выедешь, нужно немного пописать руками по аналогии с x86.
