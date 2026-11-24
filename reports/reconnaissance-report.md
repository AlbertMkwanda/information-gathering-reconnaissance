# Public Metadata Review — kwachahelper.com

**Student:** Albert Mkwanda · **Serial:** 1 · **Registration:** 23311351001  
**Project:** Information Gathering and Reconnaissance  
**Review date:** 2026-11-23  
**Scope:** Public A/AAAA DNS lookups and the exact HTTPS homepage only

## Authorization and boundaries

Permission was confirmed for a narrow public-information review. The checks covered A and AAAA DNS lookups through the system resolver, Cloudflare DNS (`1.1.1.1`), and Google Public DNS (`8.8.8.8`), plus the homepage at `https://kwachahelper.com/`. The review stopped there: it did not open the linked app frame, visit other routes, attempt a login, or test for vulnerabilities. The local report app reads saved evidence and makes no network requests.

## Executive summary

The three resolvers agreed on the A address: `8.209.69.209`. None returned an AAAA address. The homepage GET returned HTML titled “KwachaHelper”; its description presents the service as an online short-term lender in Malawi. The page also embeds an app frame, which was left unopened. A separate HEAD request waited about 20 seconds, then timed out without returning headers.

## Findings

These observations support no security finding. The review gathered public metadata; it did not test the application's controls. They tell us neither that the site is secure nor that it is vulnerable.

| Evidence ID | Check | Result |
|---|---|---|
| DNS-01 | A record | `8.209.69.209` from the system resolver and the two public resolvers checked |
| DNS-02 | AAAA record | No address answer; negative SOA response |
| HTTP-01 | HTTPS homepage GET | HTML received; title and description recorded |
| HTTP-02 | HTTPS homepage HEAD | Timed out; no response headers received |

## Limitations

- DNS answers describe 23 November 2026. The address may change, and it does not identify who operates the service.
- The review retrieved only the homepage HTML. It did not open the embedded app frame; the timed-out HEAD request returned no headers.
- No MX or TXT records, application routes, authentication, or security controls were checked.
- The page's brand does not verify its legal operator.

## Reproduction and tests

The captured results are in `data/public_review_evidence.json`. The app displays that file without contacting the site. Run `py -m unittest discover -s tests -v` to check scope validation, report generation, the API, and the local Waitress server.
