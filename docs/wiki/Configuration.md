# Configuration

Cabcrawl reads its settings from the environment, usually a `.env` file next to the code (see
`.env.example`). It checks them at start-up and refuses to start with a clear message if a
required one is missing or wrong.

| Setting | Required | What it is |
|---|---|---|
| `SECRET_KEY` | Yes | Signs sessions and forms. 32 or more random characters. Changing it signs everyone out. |
| `DATABASE_URL` | Production | `postgresql://...` in production. Without it, `sqlite:///arcade.db`. Only PostgreSQL and SQLite are supported. |
| `BASE_URL` | Before printing labels | The public address, such as `https://tracker.example.org`, with nothing after the host. QR labels encode it. |
| `SOURCE_URL` | No | Where the footer's source-code link points, for the AGPL. Defaults to this repository; set it if you run a modified copy. |
| `LOG_LEVEL` | No | `INFO` by default. Logs are `key=value` lines, read with `journalctl`. |
| `ARCADE_BACKUPS` | No | Where deploy backups are kept, for the Backups page. |
| `EASYPOST_API_KEY` | No | Shipment tracking on part requests. |
| `USE_CLOUD_STORAGE`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_BUCKET_NAME`, `AWS_REGION` | No | A copy of work-order photos in S3. |
| `MAX_PHOTOS_PER_RECORD`, `MAX_TOTAL_STORAGE_MB` | No | Photo limits. |
| `RPI_STATS_HOST`, `RPI_STATS_PORT`, `RPI_GPIO_HOST`, `RPI_GPIO_PORT` | No | The [skeeball](Skeeball-Integration) Raspberry Pi. |

The arcade's name, logo, opening hours and alert channels are set in the app, not here (see
[Administration](Administration) and [Alerts](Alerts)).

Keep `.env` out of git; it holds the database password and the secret key.
