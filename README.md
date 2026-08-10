<h1 align="center">splatoon-2</h1>

<p align="center">
  <b>Nextendo Network game server for Splatoon 2.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-PolyForm%20Shield%201.0.0-orange" alt="License: PolyForm Shield 1.0.0">
  <img src="https://img.shields.io/badge/go-1.23%2B-00ADD8" alt="Go 1.23+">
</p>

---

## What is this?

The NEX game server for **Splatoon 2** on [Nextendo Network](https://nextendo.network). It handles
authentication, matchmaking, presence, and the Splatfest-related Ranking/Utility methods the game
needs to bring its online mode up.

It is built on the [**nextendo-nex**](https://github.com/NextendoNetwork/nextendo-nex) core.

> **DataStore is a stub.** Splatoon 2 calls a number of DataStore (`0x73`) methods during the
> online bring-up. This server currently answers them with an empty success so the game proceeds;
> a full server-side DataStore implementation is not yet part of this tree. As a result, matchmaking
> is not complete out of the box — the DataStore responses are the remaining piece to implement.

## Running

```sh
cp example.env .env    # then edit .env
go run .
```

Configuration is entirely through environment variables — see [`example.env`](example.env). No
secrets are baked into the source.

## What this is not

This server ships **no** Nintendo code, keys, measured data, or copyrighted assets. It is an
independent reimplementation for use with a community-run replacement service, not affiliated with,
endorsed by, or associated with Nintendo. The NEX access key it uses is a well-known per-title value
derivable from the game itself, not a secret.

## License

Released under the **[PolyForm Shield License 1.0.0](LICENSE.md)** — source-available: read, use,
modify, and self-host, but do not use it to provide a product that competes with Nextendo Network.
