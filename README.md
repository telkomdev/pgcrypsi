# pgcrypsi

C Crypsi (https://github.com/telkomdev/c-crypsi) PostgreSQL Extension

## Motivation/ Why ?
Why not `pgcrypto` ?. At the time this plugin was created, `pgcrypto` did not support `AES GCM` yet. So this plugin is made to fulfill `AES GCM` encryption needs.

## Dependencies
- https://github.com/telkomdev/c-crypsi
- Openssl 1.1.1

## Getting started

### Building

Clone
```shell
$ git clone https://github.com/telkomdev/pgcrypsi.git
```

Install PostgreSQL Development server and client
```shell
$ sudo apt install libpq-dev
$ sudo apt-get install -y postgresql-server-dev-10
```

Compile extensions, Create and Copy SHARED Library to `/usr/lib/postgresql/10/lib/`
```shell
$ cc -fPIC -c pgcrypsi.c -I /usr/include/postgresql/10/server/
$ cc -shared -o pgcrypsi.so pgcrypsi.o
$ sudo cp pgcrypsi.so  /usr/lib/postgresql/10/lib/
```

#### Notes
To find out what `$libdir` is referring to, run the following command:
```shell
$ pg_config --pkglibdir
/usr/lib/postgresql/10/lib
```

Install extensions
```shell
$ sudo make USE_PGXS=1 install
```

### Install to Database

Login as superuser
```shell
$ sudo --login --user postgres
$ psql
```

Connect to specific Database
```shell
$ \c database_name;
```

Show installed extensions
```shell
$ select extname from pg_extension;
```

Drop extensions
```shell
$ DROP EXTENSION IF EXISTS pgcrypsi;
```

Create extensions
```shell
$ CREATE EXTENSION IF NOT EXISTS pgcrypsi;
```

### AES GCM encrypt function
- pgcrypsi_aes_128_gcm_encrypt (AES 128 bit encryption function)
- pgcrypsi_aes_192_gcm_encrypt (AES 192 bit encryption function)
- pgcrypsi_aes_256_gcm_encrypt (AES 256 bit encryption function)

### AES GCM decrypt function
- pgcrypsi_aes_128_gcm_decrypt (AES 128 bit decryption function)
- pgcrypsi_aes_192_gcm_decrypt (AES 192 bit decryption function)
- pgcrypsi_aes_256_gcm_decrypt (AES 256 bit decryption function)

### Expected key length
- AES 128: key length should be 16 bytes/char
- AES 192: key length should be 24 bytes/char
- AES 256: key length should be 32 bytes/char

### Test the extensions

Encrypt
```shell
postgres=# select pgcrypsi_aes_256_gcm_encrypt('abc$#128djdyAgbjau&YAnmcbagryt5x', 'this is dark') as res;
                                       res
----------------------------------------------------------------------------------
 90fee206d3f41bd92e45e7c876cce4e3f4ed65aeef3cbd05139677bc18d1b393a53848944ef3df05
(1 row)
```

Decrypt
```shell
postgres=# select pgcrypsi_aes_256_gcm_decrypt('abc$#128djdyAgbjau&YAnmcbagryt5x', '90fee206d3f41bd92e45e7c876cce4e3f4ed65aeef3cbd05139677bc18d1b393a53848944ef3df05') as res;
     res
--------------
 this is dark
(1 row)
```
