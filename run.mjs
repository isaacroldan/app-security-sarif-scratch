// Throwaway: uploads synthetic SARIF logs to a scratch repo and records what GitHub code scanning does.
// Usage: node run.mjs <step>   (run from ~/scratch-sarif; evidence goes to ./evidence/<step>.json)
import {execFileSync} from 'node:child_process'
import {gzipSync} from 'node:zlib'
import {mkdirSync, readFileSync, writeFileSync} from 'node:fs'

const REPO = 'isaacroldan/app-security-sarif-scratch'
const gh = (args, input) =>
  JSON.parse(execFileSync('gh', ['api', ...args], {input, encoding: 'utf8', maxBuffer: 1 << 26}) || 'null')
const git = (...args) => execFileSync('git', ['-C', 'repo', ...args], {encoding: 'utf8'}).trim()
const sleep = (s) => execFileSync('sleep', [String(s)])

const RULES = {
  CREDENTIAL_LOG_LEAKAGE: {severity: 'high', file: 'app/routes/a.ts', line: 3},
  CODE_EVAL: {severity: 'high', file: 'app/routes/b.ts', line: 3},
  INSECURE_FETCH: {severity: 'medium', file: 'app/routes/c.ts', line: 2},
  FRESH_RULE: {severity: 'low', file: 'README.md', line: 2},
}
const LEVEL = {high: 'error', medium: 'warning', low: 'note'}
const SEV = {high: '8.0', medium: '5.0', low: '2.0'}

function sarif({ruleIds = Object.keys(RULES), findings, suppressed = [], invocations, automationId}) {
  const rules = ruleIds.map((id) => ({
    id,
    shortDescription: {text: id},
    fullDescription: {text: `${id} description`},
    help: {text: `${id} help`},
    defaultConfiguration: {level: LEVEL[RULES[id].severity]},
    properties: {tags: ['security'], 'security-severity': SEV[RULES[id].severity]},
  }))
  const results = [...findings, ...suppressed].map((id) => ({
    ruleId: id,
    ruleIndex: ruleIds.indexOf(id),
    level: LEVEL[RULES[id].severity],
    message: {text: `${id} finding`},
    locations: [
      {physicalLocation: {artifactLocation: {uri: RULES[id].file}, region: {startLine: RULES[id].line}}},
    ],
    ...(suppressed.includes(id)
      ? {suppressions: [{kind: 'external', status: 'accepted', justification: 'Reviewed: synthetic test'}]}
      : {}),
    properties: {source: 'deterministic'},
  }))
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {driver: {name: 'Shopify app security check', semanticVersion: '3.0.0', rules}},
        ...(invocations ? {invocations} : {}),
        ...(automationId ? {automationDetails: {id: automationId}} : {}),
        columnKind: 'utf16CodeUnits',
        results,
      },
    ],
  }
}

const unresolvedNotification = (id) => ({
  level: 'warning',
  message: {text: `${id} is unresolved: agent_investigation_required. Run record before uploading.`},
  associatedRule: {id},
})

const STEPS = {
  full: () => sarif({findings: ['CREDENTIAL_LOG_LEAKAGE', 'CODE_EVAL']}),
  // CODE_EVAL is unresolved: a rule with no results.
  'unresolved-plain': () => sarif({findings: ['CREDENTIAL_LOG_LEAKAGE']}),
  'unresolved-failed': () =>
    sarif({
      findings: ['CREDENTIAL_LOG_LEAKAGE'],
      invocations: [{executionSuccessful: false, toolExecutionNotifications: [unresolvedNotification('CODE_EVAL')]}],
    }),
  'unresolved-successful': () =>
    sarif({
      findings: ['CREDENTIAL_LOG_LEAKAGE'],
      invocations: [{executionSuccessful: true, toolExecutionNotifications: [unresolvedNotification('CODE_EVAL')]}],
    }),
  'unresolved-error-notification': () =>
    sarif({
      findings: ['CREDENTIAL_LOG_LEAKAGE'],
      invocations: [
        {
          executionSuccessful: false,
          toolExecutionNotifications: [{...unresolvedNotification('CODE_EVAL'), level: 'error'}],
        },
      ],
    }),
  // --check-id INSECURE_FETCH, with its own category: only that rule, with a finding.
  narrowed: () =>
    sarif({
      ruleIds: ['INSECURE_FETCH'],
      findings: ['INSECURE_FETCH'],
      automationId: 'shopify-app-security/check-id/INSECURE_FETCH/',
    }),
  // Full run where CODE_EVAL (an open alert) and INSECURE_FETCH (never seen in this category) are suppressed.
  suppressed: () => sarif({findings: ['CREDENTIAL_LOG_LEAKAGE'], suppressed: ['CODE_EVAL', 'INSECURE_FETCH']}),
  // A suppressed result GitHub has never seen: a rule and location with no alert yet.
  'suppressed-fresh': () =>
    sarif({findings: ['CREDENTIAL_LOG_LEAKAGE', 'CODE_EVAL', 'INSECURE_FETCH'], suppressed: ['FRESH_RULE']}),
  // Logs written by the CLI change, with file:///apps/my-app/ made relative as upload-sarif does.
  'cli-full': () => cliLog('full'),
  'cli-narrowed': () => cliLog('narrowed'),
  empty: () => sarif({ruleIds: [], findings: []}),
}

function cliLog(name) {
  return JSON.parse(readFileSync(`gen/${name}.sarif`, 'utf8').replaceAll('file:///apps/my-app/', ''))
}

const step = process.argv[2]
const log = STEPS[step]()
git('commit', '--allow-empty', '-qm', `step: ${step}`)
git('push', '-q', 'origin', 'main')
const commit = git('rev-parse', 'HEAD')
const upload = gh(
  ['--method', 'POST', `repos/${REPO}/code-scanning/sarifs`, '--input', '-'],
  JSON.stringify({
    commit_sha: commit,
    ref: 'refs/heads/main',
    sarif: gzipSync(JSON.stringify(log)).toString('base64'),
    tool_name: 'Shopify app security check',
  }),
)
let processing
for (let i = 0; i < 40; i++) {
  sleep(5)
  processing = gh([`repos/${REPO}/code-scanning/sarifs/${upload.id}`])
  if (processing.processing_status !== 'pending') break
}
sleep(5)
const alerts = gh([`repos/${REPO}/code-scanning/alerts?per_page=100&state=open`])
  .concat(gh([`repos/${REPO}/code-scanning/alerts?per_page=100&state=fixed`]))
  .concat(gh([`repos/${REPO}/code-scanning/alerts?per_page=100&state=dismissed`]))
  .concat(gh([`repos/${REPO}/code-scanning/alerts?per_page=100&state=closed`]))
const seen = new Set()
const alertStates = alerts
  .filter((a) => !seen.has(a.number) && seen.add(a.number))
  .sort((a, b) => a.number - b.number)
  .map((a) => ({
    number: a.number,
    rule: a.rule.id,
    state: a.state,
    fixed_at: a.fixed_at,
    dismissed_reason: a.dismissed_reason,
    dismissed_comment: a.dismissed_comment,
    category: a.most_recent_instance.category,
    instance_state: a.most_recent_instance.state,
    commit: a.most_recent_instance.commit_sha.slice(0, 7),
  }))
const analyses = gh([`repos/${REPO}/code-scanning/analyses?per_page=3`]).map((a) => ({
  id: a.id,
  commit: a.commit_sha.slice(0, 7),
  category: a.category,
  results_count: a.results_count,
  rules_count: a.rules_count,
  error: a.error,
  warning: a.warning,
}))
const evidence = {step, commit, sarif: log, upload, processing, analyses, alertStates}
mkdirSync('evidence', {recursive: true})
writeFileSync(`evidence/${step}.json`, `${JSON.stringify(evidence, null, 2)}\n`)
console.log(JSON.stringify({step, commit: commit.slice(0, 7), processing, analyses: analyses.slice(0, 1), alertStates}, null, 1))
