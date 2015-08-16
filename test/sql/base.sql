\set ECHO none
BEGIN;
\i sql/passwd-fdw.sql
\set ECHO all

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

SELECT * FROM passwd;

ROLLBACK;
