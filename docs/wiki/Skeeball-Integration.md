# Skeeball integration

Cabcrawl can talk to a Raspberry Pi based skeeball scoring system, which counts balls and coins
on each lane. The integration is older than the rest of the app and hasn't been redesigned; it is
kept working as it is.

## What it does

- **Lane pages** under `/skeeball/`: an overview of the lanes, a control panel (reset a lane or
  the machine), per-lane stats and a log viewer.
- **Revenue**: once a day, each lane's coins are written as a play reading on its machine, so
  skeeball lanes show up in [reports](Reports) like any other game.
- **A simulator** for trying it without hardware.

## How it connects

The Pi runs two small servers of its own: a stats API (port 5002 by default) and a GPIO API
(port 5001 by default). Cabcrawl asks the stats API for lane figures, and falls back to its own
lane state when the Pi doesn't answer. Point it at the Pi with `RPI_STATS_HOST`, `RPI_STATS_PORT`,
`RPI_GPIO_HOST` and `RPI_GPIO_PORT` ([Configuration](Configuration)).

The Pi-side programs and their setup notes are in the repository under `docs/history/skeeball/`.

## Status

The skeeball API contract is left exactly as it is, so a lane that works today keeps working. Its
pages are only reached from `/skeeball/`, not from the main menu.
