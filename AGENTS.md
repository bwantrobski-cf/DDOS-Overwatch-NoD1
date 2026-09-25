# Project guidance

- The Cloudflare Worker and embedded UI are implemented in `src/index.js`.
- Run `npm test` after changing usage calculations or rendered UI behavior.
- Run `node --check src/index.js` to validate Worker module syntax.
- Run `wrangler deploy --dry-run` to verify the Worker bundle before deployment.
