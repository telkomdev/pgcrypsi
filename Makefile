EXTENSION = pgcrypsi        # extensions name
DATA = pgcrypsi--0.0.1.sql  # script
OBJS = pgcrypsi.o
# build
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)