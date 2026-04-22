# db

Persistent PostgreSQL data lives in `db/data`.

The `db` service mounts this folder to:

- `/var/lib/postgresql/data`

Default PostgreSQL database settings in compose:

- user: `daygle_server_manager`
- database: `daygle_server_manager`
