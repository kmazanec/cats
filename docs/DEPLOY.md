# CATS — Deploy runbook

CATS runs on the same Digital Ocean droplet as the OpenEMR Co-Pilot,
behind the host's existing Caddy reverse proxy, at
**`https://cats.biograph.dev`**. GitLab CI deploys via a shell runner
on the droplet itself — no SSH, no remote build.

This document covers: first-time bring-up, the steady-state deploy
path (auto on `main`), and the documented rollback path.

---

## 1. Prerequisites (one-time)

These need to be in place before the first green pipeline can ship to
`https://cats.biograph.dev`:

1. **DNS.** An A record for `cats.biograph.dev` pointing at the droplet's
   public IP. Verify with `dig +short cats.biograph.dev` from outside.
2. **Caddy site block** added to the host's Caddyfile (see §2 below) and
   `caddy reload` run.
3. **Deploy directory** on the droplet, owned by the GitLab runner user:

   ```bash
   sudo mkdir -p /srv/cats
   sudo chown gitlab-runner:gitlab-runner /srv/cats
   sudo -u gitlab-runner git clone <self-hosted gitlab url> /srv/cats
   ```
4. **GitLab project variables** (Project Settings → CI/CD → Variables):

   | Key                       | Type     | Notes                              |
   |---------------------------|----------|------------------------------------|
   | `CATS_DEPLOY_DIR`         | Variable | `/srv/cats`                        |
   | `CATS_ADMIN_EMAIL`        | Variable | bootstrap admin login              |
   | `CATS_ADMIN_PASSWORD`     | Masked   | bootstrap admin password           |
   | `CATS_SESSION_SECRET`     | Masked   | long random string (`openssl rand -hex 32`) |
   | `OPENROUTER_API_KEY`      | Masked   | optional in R1                     |
   | `LANGSMITH_API_KEY`       | Masked   | optional in R1                     |

5. **Runner tag** `cats-droplet` registered against the GitLab project. The
   runner uses the **shell** executor.
6. The runner's user has `docker` group membership so `docker compose` works
   without sudo.

---

## 2. Caddy site block

Add to the host's Caddyfile (alongside the existing Co-Pilot block):

```caddy
cats.biograph.dev {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8400 {
        header_up Host {host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }
    log {
        output file /var/log/caddy/cats.log
        format json
    }
}
```

Then `sudo caddy reload --config /etc/caddy/Caddyfile`.

The CATS API container binds host port 8400 (see `docker-compose.yml`),
which is the same port Caddy proxies to.

---

## 3. Steady-state deploy

Every push to `main` runs `lint` → `test-unit` → `deploy`. The deploy job
runs on the droplet and:

1. `git fetch && git reset --hard $CI_COMMIT_SHA` in `$CATS_DEPLOY_DIR`
2. exports `CATS_BUILD_SHA` and `CATS_GITLAB_PIPELINE_URL` (so the
   dashboard chrome shows the deployed SHA and links to the pipeline)
3. `docker compose up -d --build` — Alembic migrations run automatically
   from the container's `command:` line
4. smoke-tests `/healthz` from inside the host network and fails the job
   if it doesn't return 200

Failed lint/test stages do **not** deploy; the dashboard's build link
keeps showing the previous green SHA until a new green pipeline lands.

---

## 4. Rollback (rehearsed)

Two equivalent paths. Pick the one with the lowest blast radius for
your situation.

### Path A — GitLab manual job (preferred)

1. In GitLab, open the most recent pipeline on `main`.
2. Click the **`rollback`** job.
3. Set the variable `ROLLBACK_SHA` to the previous-known-good commit SHA.
4. Run.

The job does the same `git checkout` + `docker compose up -d --build`
dance, pinned to the SHA you supplied.

### Path B — manual on the droplet

```bash
ssh root@cats.biograph.dev   # or whoever owns the box
cd /srv/cats
git fetch --prune origin
git checkout <previous-good-sha>
export CATS_BUILD_SHA="$(git rev-parse --short HEAD)"
docker compose up -d --build
curl -fsS http://127.0.0.1:8400/healthz   # expect {"ok":true}
```

### Measured rollback time

Documented from rehearsal: a typical rollback from a known-bad deploy
to a known-good one is **45–90 seconds** wall time (the dominant cost
is the docker rebuild, not the git checkout). The Co-Pilot on the same
droplet is unaffected because they're separate compose projects and
Caddy keeps proxying to whatever's at `:8400`.

---

## 5. Operational checks after a deploy

Once the deploy job goes green:

1. Open `https://cats.biograph.dev/healthz` from outside the host —
   expect `{"ok": true}`.
2. Sign in to `https://cats.biograph.dev/` as the bootstrap admin and
   visit `/health` — every dependency should be `ok` or
   `not_configured`. Anything `fail` is a real problem.
3. Visit `/audit` to confirm the previous deploy's `auth.login` and any
   project mutations are present (the append-only trigger on
   `audit_log` survives container restarts because the data is in the
   `cats_pg` Postgres volume).

---

## 6. Sharing the host with the Co-Pilot

The risk laid out in `docs/ROADMAP.md` Round 1 is real: a CATS-side
incident must not affect the Co-Pilot. Mitigations in place:

- **Separate compose projects.** CATS' `docker-compose.yml` is in
  `/srv/cats`; the Co-Pilot's is in its own directory with its own
  network namespace.
- **Distinct host ports.** CATS uses `8400` (api), `5433` (postgres),
  `6380` (redis). The Co-Pilot uses its own non-overlapping set.
- **Caddy as the only public surface.** The droplet's firewall blocks
  inbound to the application ports directly; only Caddy's `:443` is
  reachable from the outside.
- **Resource envelope.** CATS' container does not pin CPU; if heavy
  use during a campaign starts crowding the Co-Pilot, add Docker
  resource constraints to `docker-compose.yml` rather than scaling
  laterally — Round 1 doesn't run campaigns yet, so this is a Round 2+
  follow-up.

---

## 7. Round 1 verification checklist

The DoD requires these to be demonstrable. Walk through them after the
first green deploy lands:

- [ ] `https://cats.biograph.dev/` is reachable from outside the host
      and serves the login page.
- [ ] Logging in as the bootstrap admin lands on the overview.
- [ ] Registering a Project via the dashboard appears in the projects
      list.
- [ ] An `audit.login` and `project.create` row appear in `/audit`
      with the admin's email as actor.
- [ ] The chrome-top "build" label shows the deployed SHA and links
      to the GitLab pipeline.
- [ ] `/health` returns green for Postgres + Redis; OpenRouter and
      LangSmith show `not_configured` until keys are set.
- [ ] During a deliberate `deploy` run, a curl loop against the
      Co-Pilot's `/healthz` shows no failures attributable to the CATS
      restart.
