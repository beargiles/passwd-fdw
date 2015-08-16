passwd-fdw
==========

This is a Foreign Data Wrapper (fdw) for the Linux/Unix user and
group databases. This is typically the /etc/passwd and /etc/group 
files but with GNU name service switching (NSS) it could come from
LDAP or other sources.

This extension has limited usefulness unless you are also using
the tarfile extension. Note: this extension can reveal sensitive
information about the server, e.g., other services installed.


Usage
-----

There are two standard files in the Linux/Unix user database.

FIXME: how to specify attributes that indicate whether it's the password or group file....

```{sql}
CREATE SERVER passwd_svr FOREIGN DATA WRAPPER passwd_fdw;

CREATE FOREIGN TABLE passwd(
   name   text,
   passwd text,
   uid    int,
   gid    int,
   gecos  text,
   dir    text,
   shell  text
) SERVER passwd_svr;

CREATE FOREIGN TABLE grp(
   name    text,
   gid     int,
   members text[]
) SERVER passwd_svr;
```

Building
--------

To build it, just do this:

    make
    make installcheck
    make install

If you encounter an error such as:

    "Makefile", line 8: Need an operator

You need to use GNU make, which may well be installed on your system as
`gmake`:

    gmake
    gmake install
    gmake installcheck

If you encounter an error such as:

    make: pg_config: Command not found

Be sure that you have `pg_config` installed and in your path. If you used a
package management system such as RPM to install PostgreSQL, be sure that the
`-devel` package is also installed. If necessary tell the build process where
to find it:

    env PG_CONFIG=/path/to/pg_config make && make installcheck && make install

And finally, if all that fails (and if you're on PostgreSQL 8.1 or lower, it
likely will), copy the entire distribution directory to the `contrib/`
subdirectory of the PostgreSQL source tree and try it there without
`pg_config`:

    env NO_PGXS=1 make && make installcheck && make install

If you encounter an error such as:

    ERROR:  must be owner of database regression

You need to run the test suite using a super user, such as the default
"postgres" super user:

    make installcheck PGUSER=postgres

Once passwd-fdw is installed, you can add it to a database. If you're running
PostgreSQL 9.1.0 or greater, it's a simple as connecting to a database as a
super user and running:

    CREATE EXTENSION passwd-fdw;

If you've upgraded your cluster to PostgreSQL 9.1 and already had passwd-fdw
installed, you can upgrade it to a properly packaged extension with:

    CREATE EXTENSION passwd-fdw FROM unpackaged;

For versions of PostgreSQL less than 9.1.0, you'll need to run the
installation script:

    psql -d mydb -f /path/to/pgsql/share/contrib/passwd-fdw.sql

If you want to install passwd-fdw and all of its supporting objects into a specific
schema, use the `PGOPTIONS` environment variable to specify the schema, like
so:

    PGOPTIONS=--search_path=extensions psql -d mydb -f passwd-fdw.sql

Dependencies
------------
The `passwd-fdw` data type has no dependencies other than PostgreSQL.

Copyright and License
---------------------

Copyright (c) 2015 Bear Giles <bgiles@coyotesong.com>.

