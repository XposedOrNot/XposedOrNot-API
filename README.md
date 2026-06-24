<h1 align="center">XposedOrNot API</h1>
 
<p align="center">
🎉 Your free API for real-time data breach monitoring and analytics. <br>
<a href="https://github.com/XposedOrNot/XposedOrNot-API/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue"></a>
<a href="https://github.com/psf/black"><img src="https://img.shields.io/static/v1?label=code%20style&message=black&color=blue"></a>
<img src="https://img.shields.io/badge/code%20style-pep8-blue.svg">
<a href="https://github.com/XposedOrNot/XposedOrNot-API/blob/master/CONTRIBUTING.md"><img src="https://img.shields.io/badge/Contributions-Welcome-brightgreen"></a>
<a href="https://github.com/XposedOrNot/XposedOrNot-API/actions/workflows/black.yml"><img src="https://github.com/XposedOrNot/XposedOrNot-API/actions/workflows/black.yml/badge.svg" alt="Black"></a>
<a href="https://github.com/XposedOrNot/XposedOrNot-API/actions/workflows/pylint.yml"><img src="https://github.com/XposedOrNot/XposedOrNot-API/actions/workflows/pylint.yml/badge.svg" alt="Pylint"></a>
 <a href="https://github.com/XposedOrNot/XposedOrNot-API/actions/workflows/codeql.yml"><img src="https://github.com/XposedOrNot/XposedOrNot-API/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
<a href="https://securityscorecards.dev/viewer/?uri=github.com/XposedOrNot/XposedOrNot-API"><img src="https://api.securityscorecards.dev/projects/github.com/XposedOrNot/XposedOrNot-API/badge" alt="OpenSSF Scorecard"></a>
<a href="https://www.bestpractices.dev/projects/11418"><img src="https://www.bestpractices.dev/projects/11418/badge?v=1" alt="OpenSSF Best Practices"></a>

<p align="center">     
    <a href="https://xposedornot.docs.apiary.io/" target="_blank">XposedOrNot API Playground</a>    ·
    <a href="https://xposedornot.com" target="_blank"> XposedOrNot.com</a>
</p> <br>  
</p>  
<p align="center">
  <img src="https://github.com/XposedOrNot/XposedOrNot-Website/blob/master/static/images/xon.webp" alt="XposedOrNot demo">
</p>


## What is XposedOrNot API?

Data breaches happen constantly, and most people only find out long after their email and passwords are already circulating. I built XposedOrNot so you don't have to wonder. Check an email or domain and know right away whether it's turned up in a known breach.

This repo is the API that powers it all: the breach lookups, the analytics, and the alerts. It's free to use, and it's open-source, so you can read exactly how every check works rather than taking my word for it.

Give it a try below, and if you find it useful, I'd love for you to build something with it.

Devanand Premkumar, creator of XposedOrNot
[![Twitter](https://img.shields.io/badge/Twitter-blue?style=flat-square&logo=twitter&logoColor=white&url=https%3A%2F%2Ftwitter.com%2Fdevaonbreaches)](https://twitter.com/devaonbreaches)
[![Mastodon](https://img.shields.io/badge/-Mastodon-blue?style=flat-square&logo=mastodon&logoColor=white&link=https://infosec.exchange/@DevaOnBreaches)](https://infosec.exchange/@DevaOnBreaches)

## Quick Example

Check if an email has been exposed in data breaches:

```bash
curl https://api.xposedornot.com/v1/check-email/test@example.com
```

Response:
```json
{
  "breaches": [["Adobe", "LinkedIn"]],
  "email": "test@example.com",
  "status": "success"
}
```

Get detailed breach analytics:
```bash
curl "https://api.xposedornot.com/v1/breach-analytics?email=test@example.com"
```

## Rate Limits & API Access

- **No API key required** for basic endpoints (`/v1/check-email`, `/v1/breach-analytics`, `/v1/breaches`)
- **Rate limits**: 2 requests/second, 100 requests/day per IP
- **API key required** for domain breach monitoring (enterprise feature)

For full documentation, see the [API docs](https://XposedOrNot.com/api_doc) and [API playground](https://xposedornot.docs.apiary.io/).

## API Endpoints

The full, always-current spec lives at [`/docs`](https://api.xposedornot.com/docs)
(Swagger) and [`/openapi.json`](https://api.xposedornot.com/openapi.json). The
endpoints you'll reach for most:

### Breach lookups
| Method | Path | What it does |
|--------|------|--------------|
| GET | `/v1/check-email/{email}` | Quick check: is this email in a known breach? |
| GET | `/v1/breach-analytics?email=` | Detailed breach analytics for an email |
| GET | `/v2/breach-analytics?email=` | Newer v2 analytics response |
| GET | `/v1/breaches` | List all known breaches (optional `?domain=`) |
| GET | `/v1/domain-breach-summary` | Summary of breaches for a domain |

### Stats & feeds
| Method | Path | What it does |
|--------|------|--------------|
| GET | `/v1/metrics` | Top-level breach metrics |
| GET | `/v1/metrics/detailed` | Expanded metrics |
| GET | `/v1/metrics/domain/{domain}` | Metrics for a single domain |
| GET | `/v1/analytics/pulse` | Recent breach activity pulse |
| GET | `/v1/xon-pulse` | XposedOrNot activity feed |
| GET | `/v1/rss` | Breach updates as an RSS feed |

### Domain monitoring (API key required)
Domain-level breach monitoring, verification, and alerting are available with an
API key. See the [API docs](https://XposedOrNot.com/api_doc) for the domain
verification and alert-subscription flows.

## Use it from your AI tools (MCP)

XposedOrNot ships a built-in [Model Context Protocol](https://modelcontextprotocol.io)
server, so AI assistants can check breaches directly. Point your MCP client at
`https://api.xposedornot.com/mcp` (JSON-RPC 2.0 over HTTP).

Tools exposed:
- **`check_email_breaches`**: check if an email appears in any known breach
- **`get_breach_analytics`**: detailed breach stats for an email
- **`list_breaches`**: list known breaches (optionally filtered by domain)

A quick `tools/list` call:

```bash
curl -X POST https://api.xposedornot.com/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

## Why use XposedOrNot API?

XposedOrNot was the first open-source tool to monitor and alert on data breaches, and this API gives you direct access to everything it has collected and keeps current. With it you can:
- Check whether an email has appeared in a known data breach, with stats on where and when
- See if an email shows up in public pastes
- Run a single combined search across both breaches and pastes
- Check whether a password has been exposed without ever revealing your identity

Prefer to just look something up without writing code? You can do all of this on the website too: https://XposedOrNot.com.


## Security

This project is fully open-source and uses automated security tooling (Black, Pylint, CodeQL, OpenSSF Scorecard). For security details, see [SECURITY.md](SECURITY.md).

## Prerequisites

- **Docker** (recommended): Docker 20.10+ and Docker Compose V2
- **Local install**: Python 3.9+, Google Cloud SDK

## Quick Start for Local Development

### Using Docker Compose (Recommended)

1. **Clone the Repository:**

    ```shell
    git clone https://github.com/XposedOrNot/XposedOrNot-API
    ```

2. **Update the necessary environment variables in the docker-compose.yml file if needed, then run:**


    ```shell
    docker compose up
    ```

    This command will build API and Datastore Docker images. Note that the project source directory is mapped in the Docker container, so any changes in the source code won't require rebuilding the Docker image.

### Local Installation

1. **Clone the Repository:**

    ```shell
    git clone https://github.com/XposedOrNot/XposedOrNot-API
    ```

2. **Install Required Packages**

    ```shell
    sudo apt-get install -y google-cloud-sdk google-cloud-sdk-app-engine-python python3-pip build-essential libffi-dev python3-dev 
    ```

3. **Install Python Libraries**


    ```shell
    pip3 install -r requirements.txt
    ```

4. **Setup Google Cloud Datastore**

    Before running XposedOrNot-API, choose one of the following options:

-   [Run local Google DataStore emulator](https://cloud.google.com/datastore/docs/tools/datastore-emulator)
    and debug using the local emulator rather than directly connect to Google DataStore. 

    ```shell
    # For posix platforms, e.g. linux, mac:
    gcloud beta emulators datastore start
    ```

-   [Authenticate to Google DataStore](https://cloud.google.com/sdk/gcloud/reference/beta/auth/application-default) and directly debug using Google DataStore.

5. **Run the application**

    ```shell
    python3 main.py
    ```

## Configuration

Configuration is read from environment variables. For Docker Compose these are
already set in `docker-compose.yml`; for a local install, copy `.env.example` to
`.env` and fill in the values (or export them in your shell).

### Required (the app won't start without these)
| Variable | What it's for |
|----------|---------------|
| `SECRET_APIKEY` | Secret used to sign issued API keys |
| `SECURITY_SALT` | Salt for signing verification tokens |
| `WTF_CSRF_SECRET_KEY` | CSRF protection secret |
| `ENCRYPTION_KEY` | Fernet key for encrypting stored data |
| `XMLAPI_KEY` | WhoisXML API key ([whoisxmlapi.com](https://www.whoisxmlapi.com/)) |
| `AUTH_EMAIL` | Cloudflare account email |
| `AUTHKEY` | Cloudflare API key |
| `CF_MAGIC` | Cloudflare integration token |
| `CF_UNBLOCK_MAGIC` | Cloudflare unblock token |
| `MJ_API_KEY` | Mailjet API key, for sending alert emails ([mailjet.com](https://www.mailjet.com/)) |
| `MJ_API_SECRET` | Mailjet API secret |

> For local development you can set these to any placeholder value; the defaults
> in `docker-compose.yml` show the expected format.

### Redis (rate limiting & state)
| Variable | Default | Notes |
|----------|---------|-------|
| `REDIS_HOST` | `localhost` | Redis host |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_DB` | `0` | Redis database number |
| `REDIS_PASSWORD` | _(none)_ | Set if your Redis requires auth |

### Google Cloud (Datastore & Pub/Sub)
| Variable | Default | Notes |
|----------|---------|-------|
| `PROJECT_ID` | _(none)_ | GCP project ID |
| `DATASTORE_EMULATOR_HOST` | _(none)_ | Point at the local emulator, e.g. `localhost:8000` |
| `TOPIC_ID` | _(none)_ | Pub/Sub topic for the live-visitor globe feed |

### Optional
| Variable | Default | Notes |
|----------|---------|-------|
| `ENVIRONMENT` | `production` | `production` or `development` |
| `BASE_URL` | `https://api.xposedornot.com` | Public base URL used in links |
| `PORT` | `8080` | Port the server listens on |
| `ENABLE_SCHEDULER` | `false` | Run the background digest scheduler |
| `DEBUG_EMAIL` | _(none)_ | Override recipient for debug emails |
| `OPENAI_API_KEY` | _(none)_ | Enables AI-assisted analytics |
| `SENIORITY_ENRICH_URL` / `SENIORITY_ENRICH_SECRET` | _(none)_ | External seniority-enrichment service |

## Contributing

Please read [CONTRIBUTING.md](https://github.com/XposedOrNot/XposedOrNot-API/blob/master/CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.


## Authors

* **Devanand Premkumar** - *Initial work* - [XposedOrNot-API](https://github.com/XposedOrNot/XposedOrNot-API)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

## Security Vulnerability Reporting

Please do not report security vulnerabilities through public GitHub issues. Instead, refer to our [Responsible Disclosure Guidelines](https://xposedornot.com/responsible-disclosure) for reporting these issues in a secure manner.


## Acknowledgments

* Thanks to the Python community and the maintainers of every library this project leans on. XposedOrNot stands on your work.

* And to everyone who has reviewed the code and reported issues: thank you. A second set of eyes catches what I can't.

## Show Your Support

If this saved you some trouble, a few things genuinely help:

- Star the repo so others can find it
- Fork it and send a pull request; contributions are welcome
- Share it with someone who'd find it useful

