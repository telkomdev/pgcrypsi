FROM postgres:12

# docker is only used for integration testing, so ignoring security is acceptable

ENV POSTGRES_USER postgres
ENV POSTGRES_PASSWORD 12345678

RUN apt-get update && apt-get install -y build-essential \ 
    && apt-get install -y gcc-multilib \
    && apt-get install -y libpq-dev \
    && apt-get install -y postgresql-server-dev-12

COPY . .

RUN cc -fPIC -c pgcrypsi.c -I /usr/include/postgresql/12/server/
RUN cc -shared -o pgcrypsi.so pgcrypsi.o
RUN cp pgcrypsi.so  /usr/lib/postgresql/12/lib/
RUN make USE_PGXS=1 install

COPY ./scripts/init.sql /docker-entrypoint-initdb.d/
COPY ./scripts/load_ext.sh /docker-entrypoint-initdb.d/