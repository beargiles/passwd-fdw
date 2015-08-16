\set ECHO none
BEGIN;
\i sql/passwd-fdw.sql
\set ECHO all

SELECT * FROM etc_passwd;

SELECT * FROM etc_group;

ROLLBACK;
