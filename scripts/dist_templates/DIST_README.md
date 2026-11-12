# RAIL - deployment package

Three folders. Two get copied to machines; one is for you to read.

| Folder | Goes to | Size | Contents |
|---|---|---|---|
| `SENDER/` | Network A | ~43 MB | full stack: inspection, ML models, private key, tooling, tests |
| `RECEIVER/` | Network B | ~0.1 MB | minimal: no inspection code, no models, public key only |
| `DOCS/` | stays with you | small | every guide, plus deployment collateral |

The 400× size difference follows from the architecture: **all inspection and
the entire ML trusted computing base sit on the source side**, so the
destination gateway - the side being protected - stays small.

## Order of work

1. Copy `SENDER/` to Network A and `RECEIVER/` to Network B.
2. Read `SENDER/START_HERE.md` and `RECEIVER/START_HERE.md`.
3. Set the peer IP and port on both sides; confirm `policy.id` matches.
4. Start the receiver **first**, then send.
5. Keep `DOCS/TESTING_GUIDE.md` open while you work.

## Which document to read when

| Question | File |
|---|---|
| How do I test this? | `DOCS/TESTING_GUIDE.md` |
| What are the ML models, and are they pretrained? | `DOCS/MODELS.md` |
| How do I block everything except RAIL? | `DOCS/NETWORK_HARDENING.md` |
| What did it actually measure? | `DOCS/RESULTS.md` |
| How does the code map to the paper? | `DOCS/ARCHITECTURE.md` |
| Install and run reference | `DOCS/RUNBOOK.md` |
| Two-VM lab setup | `DOCS/deploy/` |

## Regenerating this package

After changing anything in the project:

```bash
py scripts/package_dist.py --sender-ip 10.20.0.10 --receiver-ip 10.20.0.20
```
