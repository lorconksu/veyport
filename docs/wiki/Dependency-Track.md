# Dependency-Track

Dependency-Track provides the visual dependency and vulnerability inventory for published Veyport releases. The owner's private dashboard is at [dependencytrack-lab.yiucloud.com](https://dependencytrack-lab.yiucloud.com); access requires the local network or permitted VPN route and a Dependency-Track login.

## What appears in the dashboard

Open **Projects**, search for **Veyport**, and select the version to inspect:

| Project | Contents |
|---|---|
| Veyport / veyport | Main image OS packages and shipped Go binary dependencies |
| Veyport / audit-ingest | Audit-ingest image dependencies |
| Veyport / audit-export | Audit-export image dependencies |
| Veyport / frontend dependencies | Frontend lockfile dependencies, including development tools |

Use **Components** for versions and licenses, and **Audit Vulnerabilities** for advisories and triage. The frontend project describes the source dependency tree; it does not claim every package is present in the final browser bundle. The separately labeled synthetic demo project is test data and is not a Veyport release.

## How updates arrive

The release pipeline already publishes checksummed SBOM evidence for its exact images. A small service inside the private network checks GitHub every ten minutes, verifies the release evidence, converts the inventories to CycloneDX, and imports them into versioned projects. It obtains frontend lockfiles from the same immutable release commit without executing repository scripts. Only stable published releases from v2.0.55 onward are included; PR builds and prereleases are excluded.

The service waits for Dependency-Track to finish import and analysis before recording success. Failed imports retry, while completed versions are retained and skipped on subsequent runs. The dashboard stays private, and the service uses a dedicated upload credential rather than a personal admin login.

OSV supplies Go, npm, and Wolfi package advisories; NVD supplies CPE-based advisories. Advisory data is refreshed independently of Veyport releases, so findings can change for an unchanged release.

## Interpreting findings

A finding requires investigation; it is not proof that the vulnerable code is reachable. Development-only packages and Go reachability assessments can explain differences from pipeline results. Existing release scanners and gates are unchanged. Dependency-Track does not currently block releases or automatically apply the pipeline's findings assessments as VEX.

For installation, token rotation, scheduling, failure handling, and recovery, see the [integration runbook](https://github.com/lorconksu/veyport/tree/main/infra/dependency-track). Automation failures are visible in systemd and its journal; an external alert destination has not been configured.
