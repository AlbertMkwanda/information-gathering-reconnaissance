# Information Gathering and Reconnaissance

**Student:** Albert Mkwanda · **Serial no.:** 1 · **Registration no.:** 23311351001

On 23 November 2026, the approved review checked public DNS and the homepage at `kwachahelper.com`. The system resolver, Cloudflare, and Google all returned the same A address: `8.209.69.209`. None returned an IPv6 address. A homepage GET returned HTML describing KwachaHelper as a lending platform in Malawi. A separate HTTPS HEAD request timed out before sending back headers.

That is a narrow snapshot, not a vulnerability assessment. No security findings are claimed. The linked app frame, other routes, mail records, authentication, and security controls were not examined. The local app displays the saved observations; it does not query the site again.

## Scope and safety

- The review covered A and AAAA DNS lookups and the exact HTTPS homepage for `kwachahelper.com`.
- It did not follow the embedded app frame or look for other routes or subdomains. No login, scan, or vulnerability test was attempted.
- The evidence loader accepts only the approved coursework hostname for this review.

## Run locally

Python 3.10+:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m src.server
```

Open `http://127.0.0.1:8000/` to read the saved report. The JSON report is at `GET /api/report`; `GET /health` checks that the local app is running.

## Tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Portfolio and submission

The three portfolio pages are in `docs/`, with a GitHub Pages workflow ready to publish them. The repository URL is still a planned location. Albert must create and publish the repository, grant lecturer access, and enable Pages from his GitHub account. Pages will host the portfolio, not the Python app.
