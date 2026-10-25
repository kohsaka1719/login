'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { createRequire } = require('node:module');
const { execFileSync } = require('node:child_process');

const directory = path.resolve(process.argv[2]);
const contextPath = path.join(process.env.CONTEXT_DIR, 'context.json');
const context = JSON.parse(fs.readFileSync(contextPath, 'utf8'));
const localRequire = createRequire(path.join(directory, 'package.json'));
const coreRequire = createRequire(localRequire.resolve('@actions/core'));
const core = localRequire('@actions/core/package.json').version;
const http = coreRequire('@actions/http-client/package.json').version;
const source = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: directory, encoding: 'utf8' }).trim();
if (source !== context.source_sha || core !== context.core || http !== context.http) {
  throw new Error('Source or resolved OIDC dependencies differ from the comparison condition.');
}
const digest = file => crypto.createHash('sha256').update(fs.readFileSync(path.join(directory, file))).digest('hex');
const evidence = {
  source_sha: source,
  core,
  http,
  node: process.version,
  main_sha256: digest('lib/main/index.js'),
  cleanup_sha256: digest('lib/cleanup/index.js'),
};
fs.writeFileSync(path.join(process.env.CONTEXT_DIR, 'build.json'), JSON.stringify(evidence, null, 2) + '\n');
console.log(JSON.stringify(evidence, null, 2));
