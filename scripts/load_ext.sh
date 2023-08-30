#!/bin/sh
set -e

psql -v ON_ERROR_STOP=1 --username postgres --dbname superdevdb <<-EOSQL
  CREATE EXTENSION IF NOT EXISTS "pgcrypsi";
  select extname FROM pg_extension;
EOSQL