# Optional Greenbone stack

`upstream-compose.yaml` is a checksummed snapshot of the official Greenbone
Community Containers definition. It is intentionally separate from the core
platform compose project.

Safety and operational rules:

- Do not expose GSA, GMP, Redis, PostgreSQL, or scanner sockets publicly.
- Start the stack only for an explicitly authorized infrastructure assessment.
- Create targets and tasks through the platform connector; do not enable
  automatic discovery of neighboring addresses.
- Keep scan concurrency at one on this four-core host.
- Wait for all feed imports to complete before trusting scan coverage.
- Preserve Greenbone reports as restricted evidence and normalize only the
  findings required by the platform.
- Stop the optional stack when it is not in use.

The upstream project documents approximately 8 GB recommended RAM and 60 GB
recommended free storage. Initial feed loading can take from several minutes
to hours. The dashboard connector remains disabled until an operator creates
local credentials and explicitly enables the integration.

Source: https://greenbone.github.io/docs/latest/22.4/container/
