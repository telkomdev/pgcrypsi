# pgcrypsi

C Crypsi (https://github.com/telkomdev/c-crypsi) PostgreSQL Extension

## Motivation/ Why ?
Why not `pgcrypto` ?. At the time this plugin was created, `pgcrypto` did not support `AES GCM` yet. So this plugin is made to fulfill `AES GCM` encryption needs.

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

### Test the extensions

Encode
```shell
database_name=# select crypsi_aes_256_gcm_encrypt('abc$#128djdyAgbjau&YAnmcbagryt5x', 'this is dark') as res;
       res
------------------
 dGhpcyBpcyBkYXJr
(1 row)
```

Decode
```shell
database_name=# select crypsi_aes_256_gcm_decrypt('abc$#128djdyAgbjau&YAnmcbagryt5x', 'data') as res;
     res      
--------------
 this is dark
(1 row)
```
