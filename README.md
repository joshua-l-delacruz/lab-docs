# joshuadelacruz.solutions Portfolio Platform

Source for [joshuadelacruz.solutions](https://joshuadelacruz.solutions), Joshua Dela Cruz's IAM, cloud operations, identity governance, and incident engineering portfolio.

![Portfolio workspace overview](assets/images/realestate-workspace.png)

> **Repository role:** This is the deployment source for the main portfolio platform. Standalone applications retain their own repositories, histories, and deployment boundaries.

## Purpose

This repository is one of three primary portfolio assets alongside the IAM Support Operations Lab and IT Incident Triage & Decision Support. I designed and deployed it to present enterprise-support experience, IAM governance evidence, operational case studies, and supporting engineering work without exposing credentials or production data.

## Portfolio hierarchy

1. **IAM Support Operations Lab** - flagship evidence for JML, Risk Assessment, Access Reviews, SoD, Privileged Access, Exception Handling, Audit Evidence, and production-readiness reasoning.
2. **IT Incident Triage & Decision Support** - primary evidence for structured incident handling, response consistency, explainable routing, and human review.
3. **Lab Docs / Portfolio Platform** - primary evidence connecting the case studies, live simulator, deployment controls, and documentation narrative.
4. **Pi 2048 and C++ Calculator** - engineering proof for end-to-end application delivery and lower-level implementation.
5. **Other workspaces** - supporting evidence of range, presented outside the primary career narrative.

| Review path | Evidence |
| --- | --- |
| **Recruiter** | Role-aligned case studies, live applications, concise project summaries and interview-ready walkthroughs. |
| **Technical** | Source, tests, deployment configuration, API boundaries and reproducible local checks. |
| **Security** | Sanitized examples, owner-scoped records, private vulnerability reporting and explicit trust boundaries. |

## Portfolio areas

- `iam-support/` - IAM case study and interactive automation/human-escalation lab
- `incident-triage/` - AI-assisted n8n incident-triage case study
- `cpp-calculator/` - C++ scientific and programmer calculator case study
- `realestate/` - Philippine property transaction workspace
- `workspaces/` - domain-organized project directory
- `worker/` - Cloudflare Worker routing, security headers and protected APIs
- `migrations/` - Cloudflare D1 database migrations
- `tests/` - Worker, security-policy and page regression tests

## Delivery architecture

```text
GitHub main branch
        |
        v
Cloudflare Workers Builds
        |
        +-- Static portfolio and case studies
        +-- Worker API and security headers
        +-- Cloudflare D1 data services
        |
        v
joshuadelacruz.solutions
```

Linked applications use separate deployment boundaries where appropriate:

- Pi 2048: Rails, PostgreSQL and Docker on Render behind `2048.joshuadelacruz.solutions`
- Scientific Calculator: C++/Drogon container on Render behind `calculator.joshuadelacruz.solutions`
- Global Malware Trends: C++/Drogon illustrative defensive dashboard behind `malware.joshuadelacruz.solutions`
- Monthly Spending: local-first static application on Vercel behind `spending.joshuadelacruz.solutions`
- Luzon Road Rush: standalone browser game behind `roadrush.joshuadelacruz.solutions`

## Security and data boundaries

- Strict browser security headers are applied by the Cloudflare Worker.
- Protected mutations require same-origin requests and verified identity context.
- D1 records are owner-scoped.
- IAM identities, tickets and audit events are fictional and browser-local.
- Malware dashboard data is explicitly illustrative; no malware samples are hosted.
- Secrets and credentials are excluded from the repository.
- Vulnerabilities are reported privately according to [SECURITY.md](SECURITY.md).

## Local verification

```text
npm ci
npm test
```

The command runs:

```text
node --test tests/worker.test.mjs
```

The production deployment is managed through Cloudflare Workers Builds from the `main` branch.

Search discovery is supported by canonical page URLs, structured social metadata, `robots.txt`, `sitemap.xml` and descriptive page titles. These improve discoverability; they do not guarantee search-engine ranking or indexing.

## Related repositories

- [IAM Support Operations Lab](https://github.com/joshua-l-delacruz/iam-support-operations-lab)
- [Pi 2048 Rails App](https://github.com/joshua-l-delacruz/2048-pi-app)
- [C++ Scientific and Programmer Calculator](https://github.com/joshua-l-delacruz/scientific-calculator-cpp)
- [Global Malware Trends C++](https://github.com/joshua-l-delacruz/global-malware-trends-cpp)
- [Pi Monthly Spending](https://github.com/joshua-l-delacruz/monthly-spending)
- [Luzon Road Rush](https://github.com/joshua-l-delacruz/luzon-road-rush)
- [AI-Assisted IT Incident Triage](https://github.com/joshua-l-delacruz/ai-it-incident-triage)

## Scope

This is a personal portfolio and sanitized demonstration environment. It does not represent production systems operated for an employer or client.

## Contributing

This is primarily a personal portfolio, but focused bug reports are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Do not submit personal data, credentials, client material, or unsolicited changes to biographical content.

## License

No open-source license has been selected yet. Copyright remains with the repository owner unless a license is added.
