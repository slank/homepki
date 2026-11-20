# Upgrade and Recovery

## Upgrade

1. Create a backup archive containing SQLite DB and config.
2. Copy the new `homepki` binary to the appliance.
3. Run:
   - `scripts/upgrade.sh /path/to/new/homepki`
4. Validate:
   - service starts
   - login succeeds
   - certificate inventory loads

## Rollback

If upgrade validation fails, run:

- `scripts/rollback.sh`

Then confirm the service is healthy and inventory data is intact.

## Backup and restore

- Backup:
  - call `CreateBackupArchive(...)` from the storage package, or package the DB/config files in a tar.gz archive.
- Restore:
  - call `RestoreBackupArchive(...)` into a clean directory
  - replace `/var/lib/homepki/homepki.db` and `/etc/homepki/config.yaml` with restored files
  - restart the service

## Factory reset

- Preserve backup first.
- Remove the SQLite database using `FactoryResetSQLite(...)` or by deleting the DB file.
- Restart service and run setup wizard again.
