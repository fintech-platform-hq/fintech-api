#!/usr/bin/env bash

set -euo pipefail

BACKEND_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IOS_ROOT="${LENVER_IOS_ROOT:-$(cd "${BACKEND_ROOT}/../lenver-ios" 2>/dev/null && pwd || true)}"
DOCS_ROOT="${LENVER_DOCS_ROOT:-$(cd "${BACKEND_ROOT}/../lenver-docs" 2>/dev/null && pwd || true)}"
TEMP_BASE="${TMPDIR:-/tmp}"
TEMP_ROOT="$(mktemp -d "${TEMP_BASE%/}/lenver-compat.XXXXXX")"
PGDATA="${TEMP_ROOT}/data"
SOCKET_DIR="${TEMP_ROOT}/socket"
DB_SUPERUSER="$(id -un)"
CURRENT_STEP="initialization"
HARNESS_STARTED_EPOCH="$(date +%s)"
IOS_BUILD_STATUS="not_run"
IOS_TEST_BUILD_STATUS="not_run"
IOS_UNIT_TEST_STATUS="not_run"
IOS_UNIT_TEST_SUMMARY_JSON='{"result":"not_run"}'
SCHEMA_PARITY_STATUS="not_run"
UPGRADED_INTEGRATION_STATUS="not_run"
DOCKER_NODE24_STATUS="not_run"
DOCKER_NODE_VERSION="not_run"
DOCKER_ENGINE_VERSION="not_run"
CLEAN_SCHEMA_SHA256="not_run"
UPGRADED_SCHEMA_SHA256="not_run"
CLEAN_SCHEMA_OBJECT_COUNTS="not_run"
UPGRADED_SCHEMA_OBJECT_COUNTS="not_run"

fail() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

for command_name in node npm initdb pg_ctl psql pg_dump createdb python3 git xcodebuild xcrun diff; do
  command -v "$command_name" >/dev/null 2>&1 || fail "$command_name is required."
done

case "$TEMP_ROOT" in
  "${TEMP_BASE%/}/lenver-compat."*) ;;
  *) fail "Refusing to use a temporary path outside the compatibility harness prefix." ;;
esac

cleanup() {
  if [[ -f "${PGDATA}/postmaster.pid" ]]; then
    pg_ctl -D "$PGDATA" --mode=fast --wait stop >/dev/null 2>&1 || true
  fi
  rm -rf -- "$TEMP_ROOT"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

run_step() {
  local step="$1"
  shift
  printf '\n== %s ==\n' "$step"
  if "$@" >"${TEMP_ROOT}/${step// /_}.log" 2>&1; then
    tail -n 12 "${TEMP_ROOT}/${step// /_}.log"
  else
    cat "${TEMP_ROOT}/${step// /_}.log" >&2
    return 1
  fi
}

cd "$BACKEND_ROOT"
mkdir -p "$SOCKET_DIR"

CURRENT_STEP="backend unit tests"
run_step "$CURRENT_STEP" npm test -- --runInBand
CURRENT_STEP="backend production build"
run_step "$CURRENT_STEP" npm run build
CURRENT_STEP="backend changed-file lint"
run_step "$CURRENT_STEP" npm exec -- eslint \
  src/app.controller.ts \
  src/app.controller.spec.ts \
  src/common/database/database.service.ts \
  test/app.e2e-spec.ts \
  test/compatibility-upgrade.spec.ts
CURRENT_STEP="backend HTTP tests"
run_step "$CURRENT_STEP" npm run test:e2e -- --runInBand

CURRENT_STEP="iOS Release-Staging generic build"
if run_step "$CURRENT_STEP" xcodebuild \
    -project "${IOS_ROOT}/Lenver.xcodeproj" \
    -scheme Lenver \
    -configuration StagingRelease \
    -destination 'generic/platform=iOS' \
    -derivedDataPath "${TEMP_ROOT}/ios-derived-data" \
    LENVER_STAGING_API_BASE_URL=https://staging.example.test \
    CODE_SIGNING_ALLOWED=NO build; then
  IOS_BUILD_STATUS="passed"
else
  IOS_BUILD_STATUS="failed"
fi

CURRENT_STEP="iOS StagingRelease unit and UI test target compilation"
if run_step "$CURRENT_STEP" xcodebuild \
    -project "${IOS_ROOT}/Lenver.xcodeproj" \
    -scheme Lenver \
    -configuration StagingRelease \
    -destination 'generic/platform=iOS Simulator' \
    -derivedDataPath "${TEMP_ROOT}/ios-test-derived-data" \
    LENVER_STAGING_API_BASE_URL=https://staging.example.test \
    ENABLE_TESTABILITY=YES \
    CODE_SIGNING_ALLOWED=NO build-for-testing; then
  IOS_TEST_BUILD_STATUS="passed"
else
  IOS_TEST_BUILD_STATUS="failed"
fi

if [[ -n "${IOS_SIMULATOR_UDID:-}" ]]; then
  CURRENT_STEP="iOS StagingRelease Simulator unit tests"
  if run_step "$CURRENT_STEP" xcodebuild \
      -project "${IOS_ROOT}/Lenver.xcodeproj" \
      -scheme Lenver \
      -configuration StagingRelease \
      -destination "platform=iOS Simulator,id=${IOS_SIMULATOR_UDID}" \
      -derivedDataPath "${TEMP_ROOT}/ios-test-derived-data" \
      LENVER_STAGING_API_BASE_URL=https://staging.example.test \
      ENABLE_TESTABILITY=YES \
      CODE_SIGNING_ALLOWED=NO \
      -only-testing:LenverTests test; then
    IOS_UNIT_TEST_STATUS="passed"
  else
    IOS_UNIT_TEST_STATUS="failed"
  fi
  IOS_TEST_LOG="${TEMP_ROOT}/iOS_StagingRelease_Simulator_unit_tests.log"
  IOS_TEST_RESULT_BUNDLE="$(sed -nE 's/^[[:space:]]*(\/.*\.xcresult)$/\1/p' "$IOS_TEST_LOG" | tail -n 1)"
  if [[ -d "$IOS_TEST_RESULT_BUNDLE" ]] \
    && xcrun xcresulttool get test-results summary --path "$IOS_TEST_RESULT_BUNDLE" --format json >"${TEMP_ROOT}/ios-test-summary.json"; then
    IOS_UNIT_TEST_SUMMARY_JSON="$(node -e 'const d = JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8")); console.log(JSON.stringify({ result: d.result, total: d.totalTestCount, passed: d.passedTests, failed: d.failedTests, skipped: d.skippedTests }))' "${TEMP_ROOT}/ios-test-summary.json")"
  fi
  if [[ "$IOS_UNIT_TEST_STATUS" == "passed" ]]; then
    IOS_UNIT_TEST_SUMMARY_RESULT="$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).result)' "$IOS_UNIT_TEST_SUMMARY_JSON")"
    [[ "$IOS_UNIT_TEST_SUMMARY_RESULT" == "Passed" ]] || fail "The iOS test command succeeded but its result bundle is not Passed."
  fi
else
  IOS_UNIT_TEST_STATUS="not_run_no_isolated_simulator"
fi

if [[ "${VALIDATE_NODE24_DOCKER:-0}" == "1" ]]; then
  command -v docker >/dev/null 2>&1 || fail "docker is required for Node 24 image validation."
  DOCKER_ENGINE_VERSION="$(docker info --format '{{.ServerVersion}}')" || fail "Docker Engine is unavailable."
  DOCKER_IMAGE_TAG="lenver-v0-compat:node24-$$"
  CURRENT_STEP="Node 24 Docker image build"
  run_step "$CURRENT_STEP" docker build --no-cache --tag "$DOCKER_IMAGE_TAG" .
  CURRENT_STEP="Node 24 Docker image runtime version"
  run_step "$CURRENT_STEP" docker run --rm "$DOCKER_IMAGE_TAG" node --version
  DOCKER_NODE_VERSION="$(tr -d '\r\n' < "${TEMP_ROOT}/Node_24_Docker_image_runtime_version.log")"
  [[ "$DOCKER_NODE_VERSION" == v24.* ]] || fail "Expected Node.js 24 in the Docker image, found $DOCKER_NODE_VERSION."
  DOCKER_NODE24_STATUS="passed"
fi

SCHEMA_VERSION="$(node -p "require('./dist/common/database/schema-compatibility').COMPATIBILITY_SCHEMA_VERSION")"
[[ "$SCHEMA_VERSION" == "20261127_v1_method_receipts" ]] || fail "Unexpected API schema compatibility version: $SCHEMA_VERSION"

CURRENT_STEP="starting isolated PostgreSQL"
PGPORT="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
initdb --no-locale --encoding=UTF8 --auth-local=trust --auth-host=trust --username="$DB_SUPERUSER" -D "$PGDATA" >"${TEMP_ROOT}/initdb.log" 2>&1 || {
  cat "${TEMP_ROOT}/initdb.log" >&2
  fail "Could not initialize the disposable PostgreSQL cluster."
}
pg_ctl -D "$PGDATA" -l "${TEMP_ROOT}/postgres.log" -o "-c listen_addresses=127.0.0.1 -p ${PGPORT} -k ${SOCKET_DIR}" --wait start >"${TEMP_ROOT}/pg-start.log" 2>&1 || {
  cat "${TEMP_ROOT}/pg-start.log" >&2
  cat "${TEMP_ROOT}/postgres.log" >&2
  fail "Could not start the disposable PostgreSQL cluster."
}

psql_db() {
  local database="$1"
  shift
  psql -X --no-password -v ON_ERROR_STOP=1 -h "$SOCKET_DIR" -p "$PGPORT" -U "$DB_SUPERUSER" -d "$database" "$@"
}

create_db() {
  createdb -h "$SOCKET_DIR" -p "$PGPORT" -U "$DB_SUPERUSER" "$1"
}

POSTGRES_VERSION="$(psql_db postgres -Atc 'SHOW server_version')"
EXPECTED_POSTGRES_MAJOR="${COMPATIBILITY_POSTGRES_MAJOR:-16}"
[[ "${POSTGRES_VERSION%%.*}" == "$EXPECTED_POSTGRES_MAJOR" ]] || fail "Expected PostgreSQL $EXPECTED_POSTGRES_MAJOR, found $POSTGRES_VERSION."

CURRENT_STEP="clean schema bootstrap and invariant checks"
create_db lenver_bootstrap_test
psql_db lenver_bootstrap_test -f db.sql >"${TEMP_ROOT}/bootstrap.log" 2>&1 || {
  cat "${TEMP_ROOT}/bootstrap.log" >&2
  fail "Clean schema bootstrap failed."
}
psql_db lenver_bootstrap_test -f test/fixtures/compatibility/bootstrap-invariants.sql >"${TEMP_ROOT}/bootstrap-invariants.log" 2>&1 || {
  cat "${TEMP_ROOT}/bootstrap-invariants.log" >&2
  fail "Clean bootstrap invariants failed."
}
psql_db lenver_bootstrap_test -f test/fixtures/compatibility/missing-schema-marker.sql >"${TEMP_ROOT}/bootstrap-missing-marker.log" 2>&1 || {
  cat "${TEMP_ROOT}/bootstrap-missing-marker.log" >&2
  fail "Clean bootstrap marker check did not detect a missing row."
}
printf 'PASS: clean bootstrap, schema version, opening-base version, holder ownership, one promoted account, and legacy-writer fence.\n'

CURRENT_STEP="representative pre-I1 to I1-I5 upgrade"
create_db lenver_upgrade_test
psql_db lenver_upgrade_test -f test/fixtures/compatibility/pre-i1.sql >"${TEMP_ROOT}/pre-i1.log" 2>&1 || {
  cat "${TEMP_ROOT}/pre-i1.log" >&2
  fail "Could not load the pinned pre-I1 schema fixture."
}
psql_db lenver_upgrade_test -f test/fixtures/compatibility/legacy-data.sql >"${TEMP_ROOT}/legacy-seed.log" 2>&1 || {
  cat "${TEMP_ROOT}/legacy-seed.log" >&2
  fail "Could not seed synthetic pre-I1 records."
}

for migration in \
  migrations/20261123_add_mvp_account_base.sql \
  migrations/20261123_enable_mvp_transaction_registration.sql \
  migrations/20261123_record_mvp_balance_checks.sql; do
  psql_db lenver_upgrade_test -f "$migration" >"${TEMP_ROOT}/migration.log" 2>&1 || {
    cat "${TEMP_ROOT}/migration.log" >&2
    fail "Upgrade failed at $migration."
  }
done

psql_db lenver_upgrade_test -f test/fixtures/compatibility/upgrade-account.sql >"${TEMP_ROOT}/upgrade-account.log" 2>&1 || {
  cat "${TEMP_ROOT}/upgrade-account.log" >&2
  fail "Could not add the synthetic I1 account before later upgrades."
}

for migration in \
  migrations/20261123_recover_mvp_expenses.sql \
  migrations/20261123_audit_mvp_corrections.sql \
  migrations/20261123_correct_mvp_opening_balance.sql \
  migrations/20261126_compatibility_schema_version.sql \
  migrations/20261127_identity_session.sql \
  migrations/20261127_identity_method_receipts.sql; do
  psql_db lenver_upgrade_test -f "$migration" >"${TEMP_ROOT}/migration.log" 2>&1 || {
    cat "${TEMP_ROOT}/migration.log" >&2
    fail "Upgrade failed at $migration."
  }
done
psql_db lenver_upgrade_test -f test/fixtures/compatibility/upgrade-assertions.sql >"${TEMP_ROOT}/upgrade-invariants.log" 2>&1 || {
  cat "${TEMP_ROOT}/upgrade-invariants.log" >&2
  fail "Upgrade preservation assertions failed."
}
psql_db lenver_upgrade_test -f test/fixtures/compatibility/missing-schema-marker.sql >"${TEMP_ROOT}/upgrade-missing-marker.log" 2>&1 || {
  cat "${TEMP_ROOT}/upgrade-missing-marker.log" >&2
  fail "Upgraded schema marker check did not detect a missing row."
}
printf 'PASS: pinned pre-I1 schema upgraded through I1-I5; legacy movement and receipt retained; I5 opening-base history recorded.\n'

CURRENT_STEP="clean and upgraded schema structural comparison"
run_step "clean schema catalog dump" pg_dump \
  --schema-only --no-owner --no-privileges --schema=public \
  -h "$SOCKET_DIR" -p "$PGPORT" -U "$DB_SUPERUSER" \
  --file="${TEMP_ROOT}/clean-schema.sql" lenver_bootstrap_test
run_step "upgraded schema catalog dump" pg_dump \
  --schema-only --no-owner --no-privileges --schema=public \
  -h "$SOCKET_DIR" -p "$PGPORT" -U "$DB_SUPERUSER" \
  --file="${TEMP_ROOT}/upgraded-schema.sql" lenver_upgrade_test
sed -E '/^\\(un)?restrict [[:alnum:]]+$/d' "${TEMP_ROOT}/clean-schema.sql" >"${TEMP_ROOT}/clean-schema-normalized.sql"
sed -E '/^\\(un)?restrict [[:alnum:]]+$/d' "${TEMP_ROOT}/upgraded-schema.sql" >"${TEMP_ROOT}/upgraded-schema-normalized.sql"
if ! diff -u "${TEMP_ROOT}/clean-schema-normalized.sql" "${TEMP_ROOT}/upgraded-schema-normalized.sql" >"${TEMP_ROOT}/schema-parity.diff"; then
  cat "${TEMP_ROOT}/schema-parity.diff" >&2
  fail "Clean bootstrap and upgraded schema differ structurally."
fi
SCHEMA_OBJECT_COUNTS_SQL="SELECT 'tables=' || (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')) || ' constraints=' || (SELECT count(*) FROM pg_constraint c WHERE c.connamespace = 'public'::regnamespace) || ' indexes=' || (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind IN ('i', 'I')) || ' functions=' || (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public' AND p.prokind IN ('f', 'p')) || ' triggers=' || (SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND NOT t.tgisinternal);"
CLEAN_SCHEMA_OBJECT_COUNTS="$(psql_db lenver_bootstrap_test -Atc "$SCHEMA_OBJECT_COUNTS_SQL")"
UPGRADED_SCHEMA_OBJECT_COUNTS="$(psql_db lenver_upgrade_test -Atc "$SCHEMA_OBJECT_COUNTS_SQL")"
[[ "$CLEAN_SCHEMA_OBJECT_COUNTS" == "$UPGRADED_SCHEMA_OBJECT_COUNTS" ]] || fail "Schema object counts differ despite matching catalog dumps."
CLEAN_SCHEMA_SHA256="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "${TEMP_ROOT}/clean-schema-normalized.sql")"
UPGRADED_SCHEMA_SHA256="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "${TEMP_ROOT}/upgraded-schema-normalized.sql")"
SCHEMA_PARITY_STATUS="passed"
printf 'PASS: clean and upgraded catalogs match exactly (%s); %s\n' "$CLEAN_SCHEMA_SHA256" "$CLEAN_SCHEMA_OBJECT_COUNTS"

CURRENT_STEP="upgraded-schema API and readiness integration"
TEST_DATABASE_URL="postgresql://${DB_SUPERUSER}@127.0.0.1:${PGPORT}/lenver_upgrade_test" \
  run_step "$CURRENT_STEP" npm run test:compatibility-upgrade
UPGRADED_INTEGRATION_STATUS="passed"

CURRENT_STEP="existing PostgreSQL integration suite"
create_db lenver_compatibility_test
psql_db lenver_compatibility_test -f db.sql >"${TEMP_ROOT}/integration-bootstrap.log" 2>&1 || {
  cat "${TEMP_ROOT}/integration-bootstrap.log" >&2
  fail "Could not initialize the isolated integration-test database."
}
TEST_DATABASE_URL="postgresql://${DB_SUPERUSER}@127.0.0.1:${PGPORT}/lenver_compatibility_test" \
  run_step "$CURRENT_STEP" npm run test:integration

CURRENT_STEP="compatibility provenance manifest"
COMPATIBILITY_SCHEMA_VERSION="$SCHEMA_VERSION" \
POSTGRES_VERSION="$POSTGRES_VERSION" \
LENVER_IOS_ROOT="$IOS_ROOT" \
LENVER_DOCS_ROOT="$DOCS_ROOT" \
COMPATIBILITY_MANIFEST_PATH="${COMPATIBILITY_MANIFEST_PATH:-}" \
HARNESS_DURATION_SECONDS="$(( $(date +%s) - HARNESS_STARTED_EPOCH ))" \
IOS_STAGING_BUILD_STATUS="$IOS_BUILD_STATUS" \
IOS_TEST_BUILD_STATUS="$IOS_TEST_BUILD_STATUS" \
IOS_UNIT_TEST_STATUS="$IOS_UNIT_TEST_STATUS" \
IOS_UNIT_TEST_SUMMARY_JSON="$IOS_UNIT_TEST_SUMMARY_JSON" \
IOS_SIMULATOR_UDID="${IOS_SIMULATOR_UDID:-not_run}" \
SCHEMA_PARITY_STATUS="$SCHEMA_PARITY_STATUS" \
UPGRADED_INTEGRATION_STATUS="$UPGRADED_INTEGRATION_STATUS" \
DOCKER_NODE24_STATUS="$DOCKER_NODE24_STATUS" \
DOCKER_NODE_VERSION="$DOCKER_NODE_VERSION" \
DOCKER_ENGINE_VERSION="$DOCKER_ENGINE_VERSION" \
CLEAN_SCHEMA_SHA256="$CLEAN_SCHEMA_SHA256" \
UPGRADED_SCHEMA_SHA256="$UPGRADED_SCHEMA_SHA256" \
CLEAN_SCHEMA_OBJECT_COUNTS="$CLEAN_SCHEMA_OBJECT_COUNTS" \
UPGRADED_SCHEMA_OBJECT_COUNTS="$UPGRADED_SCHEMA_OBJECT_COUNTS" \
node <<'NODE'
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const backend = process.cwd();
const ios = process.env.LENVER_IOS_ROOT;
const docs = process.env.LENVER_DOCS_ROOT;
const sha256 = (file) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const git = (root, args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
const repository = (root) => {
  if (!root || !fs.existsSync(path.join(root, '.git'))) return null;
  return {
    revision: git(root, ['log', '-1', '--format=%H']),
    workingTreeClean: git(root, ['status', '--porcelain', '--untracked-files=all']) === '',
  };
};
const hashFiles = (root, files) => Object.fromEntries(
  files.filter((file) => fs.existsSync(path.join(root, file)))
    .map((file) => [file, sha256(path.join(root, file))]),
);
const parseCounts = (value) => Object.fromEntries(
  value.split(/\s+/).map((item) => item.split('=')),
);
const migrationNames = [
  'migrations/20261123_add_mvp_account_base.sql',
  'migrations/20261123_enable_mvp_transaction_registration.sql',
  'migrations/20261123_record_mvp_balance_checks.sql',
  'migrations/20261123_recover_mvp_expenses.sql',
  'migrations/20261123_audit_mvp_corrections.sql',
  'migrations/20261123_correct_mvp_opening_balance.sql',
  'migrations/20261126_compatibility_schema_version.sql',
  'migrations/20261127_identity_session.sql',
  'migrations/20261127_identity_method_receipts.sql',
];
const manifest = {
  formatVersion: 1,
  result: [
    process.env.IOS_STAGING_BUILD_STATUS,
    process.env.IOS_TEST_BUILD_STATUS,
    process.env.IOS_UNIT_TEST_STATUS,
    process.env.SCHEMA_PARITY_STATUS,
    process.env.UPGRADED_INTEGRATION_STATUS,
    process.env.DOCKER_NODE24_STATUS,
  ].every((status) => status === 'passed') ? 'passed' : 'partial',
  durationSeconds: Number(process.env.HARNESS_DURATION_SECONDS),
  runtime: {
    node: process.version,
    postgres: process.env.POSTGRES_VERSION,
    xcode: execFileSync('xcodebuild', ['-version'], { encoding: 'utf8' }).trim(),
    swift: execFileSync('swift', ['--version'], { encoding: 'utf8' }).trim(),
  },
  schema: {
    compatibilityVersion: process.env.COMPATIBILITY_SCHEMA_VERSION,
    cleanBootstrapSha256: sha256(path.join(backend, 'db.sql')),
    structuralComparison: {
      status: process.env.SCHEMA_PARITY_STATUS,
      cleanBootstrapSha256: process.env.CLEAN_SCHEMA_SHA256,
      upgradedSchemaSha256: process.env.UPGRADED_SCHEMA_SHA256,
      cleanObjectCounts: parseCounts(process.env.CLEAN_SCHEMA_OBJECT_COUNTS),
      upgradedObjectCounts: parseCounts(process.env.UPGRADED_SCHEMA_OBJECT_COUNTS),
    },
    preI1Fixture: {
      sourceCommit: '3d9460708100339774eba811e8c7f21510211cb8',
      sha256: sha256(path.join(backend, 'test/fixtures/compatibility/pre-i1.sql')),
    },
    migrations: migrationNames.map((file) => ({ file, sha256: sha256(path.join(backend, file)) })),
  },
  contracts: { openapiSha256: sha256(path.join(backend, 'openapi.yaml')) },
  docker: {
    engineVersion: process.env.DOCKER_ENGINE_VERSION,
    node24ImageStatus: process.env.DOCKER_NODE24_STATUS,
    imageNodeVersion: process.env.DOCKER_NODE_VERSION,
  },
  simulator: {
    destination: process.env.IOS_SIMULATOR_UDID,
    unitTests: process.env.IOS_UNIT_TEST_STATUS,
    unitTestSummary: JSON.parse(process.env.IOS_UNIT_TEST_SUMMARY_JSON || 'null'),
  },
  repositories: {
    backend: repository(backend),
    ios: repository(ios),
    docs: repository(docs),
  },
  fileSha256: {
    backend: hashFiles(backend, ['Dockerfile', 'package-lock.json', 'db.sql', 'openapi.yaml', 'scripts/verify-compatibility.sh', 'src/app.controller.ts', 'src/app.controller.spec.ts', 'src/common/database/database.service.ts', 'src/common/database/schema-compatibility.ts', 'test/app.e2e-spec.ts', 'test/compatibility-upgrade.spec.ts', 'test/jest-upgrade.json', 'test/fixtures/compatibility/legacy-data.sql', 'test/fixtures/compatibility/bootstrap-invariants.sql', 'test/fixtures/compatibility/missing-schema-marker.sql', 'test/fixtures/compatibility/upgrade-account.sql', 'test/fixtures/compatibility/upgrade-assertions.sql']),
    ios: hashFiles(ios || '', ['Lenver.xcodeproj/project.pbxproj', 'StagingRelease-Info.plist', 'Lenver/AppEnvironment.swift', 'Lenver/LenverApp.swift', 'LenverTests/AppEnvironmentTests.swift', 'LenverTests/Authentication/AuthenticationTests.swift']),
    docs: hashFiles(docs || '', ['README.md', 'architecture/eng01/README.md', 'architecture/eng01/architecture.md', 'architecture/eng01/data-and-contracts.md', 'architecture/eng01/delivery-and-verification.md', 'architecture/eng01/security-and-privacy.md', 'architecture/eng01/v0.1-compatibility-closure.pt-BR.md']),
  },
  checks: {
    backendUnit: 'passed',
    backendBuild: 'passed',
    backendChangedFileLint: 'passed',
    backendHttp: 'passed',
    iosStagingGenericBuild: process.env.IOS_STAGING_BUILD_STATUS,
    iosTestTargetsCompile: process.env.IOS_TEST_BUILD_STATUS,
    iosUnitTests: process.env.IOS_UNIT_TEST_STATUS,
    dockerNode24Image: process.env.DOCKER_NODE24_STATUS,
    cleanBootstrap: 'passed',
    representativeUpgrade: 'passed',
    schemaParity: process.env.SCHEMA_PARITY_STATUS,
    upgradedSchemaIntegration: process.env.UPGRADED_INTEGRATION_STATUS,
    postgresIntegration: 'passed',
  },
};
const output = `${JSON.stringify(manifest, null, 2)}\n`;
const outputPath = process.env.COMPATIBILITY_MANIFEST_PATH;
if (outputPath) {
  const absolutePath = path.resolve(outputPath);
  const temporaryPath = `${absolutePath}.${process.pid}.tmp`;
  fs.writeFileSync(temporaryPath, output, { mode: 0o644, flag: 'wx' });
  fs.renameSync(temporaryPath, absolutePath);
}
process.stdout.write(output);
NODE

if [[ "$IOS_BUILD_STATUS" == "passed" \
  && "$IOS_TEST_BUILD_STATUS" == "passed" \
  && "$IOS_UNIT_TEST_STATUS" == "passed" \
  && "$SCHEMA_PARITY_STATUS" == "passed" \
  && "$UPGRADED_INTEGRATION_STATUS" == "passed" \
  && "$DOCKER_NODE24_STATUS" == "passed" ]]; then
  printf '\nCompatibility harness passed on Node %s and PostgreSQL %s.\n' "$(node --version)" "$POSTGRES_VERSION"
else
  printf '\nBackend/PostgreSQL checks passed, but an iOS StagingRelease build check failed. Review the generated partial manifest and build log.\n' >&2
  exit 1
fi
