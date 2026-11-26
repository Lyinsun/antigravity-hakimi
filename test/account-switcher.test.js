'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const switcher = require(path.join(ROOT, 'payload', 'dist', 'meter-account-switcher.js'));
const coldHelper = require(path.join(ROOT, 'payload', 'dist', 'meter-account-cold-helper.js'));
const modularInstaller = require(path.join(ROOT, 'payload', 'dist', 'modular-installer.js'));
const { PAYLOAD_FILES } = require(path.join(ROOT, 'scripts', 'pack-hakimi-asar.js'));

function makeMockKeychain(initial = {}) {
  const store = new Map();
  for (const [k, v] of Object.entries(initial)) {
    store.set(k, v);
  }
  const key = (s, a) => `${s}::${a}`;
  const calls = { has: [], get: [], set: [], delete: [] };
  return {
    store,
    calls,
    has(service, account) {
      calls.has.push([service, account]);
      return store.has(key(service, account));
    },
    get(service, account) {
      calls.get.push([service, account]);
      return store.has(key(service, account)) ? store.get(key(service, account)) : null;
    },
    set(service, account, value) {
      calls.set.push([service, account]);
      store.set(key(service, account), value);
      return true;
    },
    delete(service, account) {
      calls.delete.push([service, account]);
      return store.delete(key(service, account));
    },
  };
}

function encodeGoKeyringSecret(obj) {
  return 'go-keyring-base64:' + Buffer.from(JSON.stringify(obj), 'utf8').toString('base64');
}

function withTempDir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hakimi-cold-acc-'));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('shellEscapeForSecurity quotes safely and blocks control characters', () => {
  assert.equal(switcher.shellEscapeForSecurity('gemini'), 'gemini');
  assert.equal(switcher.shellEscapeForSecurity('user@example.com'), 'user@example.com');
  assert.equal(switcher.shellEscapeForSecurity(''), "''");
  assert.equal(switcher.shellEscapeForSecurity("a'b c"), "'a'\"'\"'b c'");
  assert.throws(() => switcher.shellEscapeForSecurity('bad\nline'), /illegal control characters/i);
  assert.throws(() => switcher.shellEscapeForSecurity('bad\rline'), /illegal control characters/i);
  assert.throws(() => switcher.shellEscapeForSecurity('bad\0nul'), /illegal control characters/i);
});

test('createMacOsKeychainAdapter uses metadata-only has() without -w and stdin security -i for set()', () => {
  const recorded = [];
  const adapter = switcher.createMacOsKeychainAdapter((bin, args, opts) => {
    recorded.push({ bin, args, input: opts?.input || '' });
    if (args[0] === 'find-generic-password' && !args.includes('-w')) {
      return 'keychain metadata without secret';
    }
    if (args[0] === 'find-generic-password' && args.includes('-w')) {
      return 'go-keyring-base64:e30=\n';
    }
    return '';
  });

  assert.equal(adapter.has('antigravity-hakimi-accounts', 'a@test.com'), true);
  assert.equal(recorded[0].bin, '/usr/bin/security');
  assert.deepEqual(recorded[0].args, ['find-generic-password', '-s', 'antigravity-hakimi-accounts', '-a', 'a@test.com']);
  assert.equal(recorded[0].args.includes('-w'), false);

  const secret = 'go-keyring-base64:TOP_SECRET_REFRESH_TOKEN';
  adapter.set('antigravity-hakimi-accounts', 'a@test.com', secret);
  assert.equal(recorded[1].bin, '/usr/bin/security');
  assert.deepEqual(recorded[1].args, ['-i']);
  assert.equal(recorded[1].args.join(' ').includes('TOP_SECRET'), false);
  assert.ok(recorded[1].input.includes('add-generic-password -U'));
  assert.ok(recorded[1].input.includes(secret));
});

test('getAccountsStatus uses metadata-only has() with zero -w reads when currentEmail matches saved profile', () => {
  withTempDir((tmp) => {
    const secretA = encodeGoKeyringSecret({ id_token_email: 'alice@work.com', refresh_token: 'rt-alice-1' });
    const secretB = encodeGoKeyringSecret({ id_token_email: 'bob@home.com', refresh_token: 'rt-bob-1' });
    const kc = makeMockKeychain({
      'gemini::antigravity': secretA,
      'antigravity-hakimi-accounts::alice@work.com': secretA,
      'antigravity-hakimi-accounts::bob@home.com': secretB,
    });
    switcher.saveProfilesRegistry(
      {
        profiles: [
          { id: 'alice@work.com', email: 'alice@work.com', label: 'Work', tierName: 'Pro', tokenFingerprint: switcher.computeTokenFingerprint(secretA) },
          { id: 'bob@home.com', email: 'bob@home.com', label: 'Personal', tierName: 'Ultra', tokenFingerprint: switcher.computeTokenFingerprint(secretB) },
        ],
      },
      { stateDir: tmp }
    );

    const status = switcher.getAccountsStatus({
      platform: 'darwin',
      stateDir: tmp,
      keychain: kc,
      currentEmail: 'alice@work.com',
      currentTierName: 'Pro',
      detectAgyCliImpl: () => [],
    });

    assert.equal(status.ok, true);
    assert.equal(status.hasActiveToken, true);
    assert.equal(status.activeProfileId, 'alice@work.com');
    assert.equal(status.currentUnsaved, false);
    assert.equal(status.agyCliRunning, false);
    assert.equal(status.profiles.length, 2);
    assert.equal(status.profiles[0].vaultPresent, true);
    assert.equal(status.profiles[1].vaultPresent, true);
    // Crucial privacy guarantee: ZERO `-w` plaintext Keychain reads during normal status refresh!
    assert.equal(kc.calls.get.length, 0);
    assert.ok(kc.calls.has.length >= 3);
  });
});

test('extractEmailHintFromSecret reads id_token_email and extractTierHintFromSecret distinguishes Ultra 5x vs 20x', () => {
  const blobPlain = encodeGoKeyringSecret({
    id_token_email: 'Alice.Work@Example.COM',
    tier_display_name: 'Google AI Ultra',
    token: { refresh_token: 'secret-never-returned' },
  });
  assert.equal(switcher.extractEmailHintFromSecret(blobPlain), 'alice.work@example.com');
  assert.equal(switcher.extractTierHintFromSecret(blobPlain), 'Google AI Ultra');

  const blob5x = encodeGoKeyringSecret({
    id_token_email: 'five@example.com',
    user_tier: 'g1-ultra-lite-tier',
    tier_display_name: 'Google AI Ultra',
  });
  assert.equal(switcher.extractTierHintFromSecret(blob5x), 'Google AI Ultra 5x');

  const blob20x = encodeGoKeyringSecret({
    id_token_email: 'twenty@example.com',
    user_tier: 'g1-ultra-tier',
    tier_display_name: 'Google AI Ultra',
  });
  assert.equal(switcher.extractTierHintFromSecret(blob20x), 'Google AI Ultra 20x');

  const blobEnterprise = encodeGoKeyringSecret({
    id_token_email: 'corp@example.com',
    user_tier: 'gcp-ge-ultra-tier',
    tier_display_name: 'Google AI Ultra',
  });
  assert.equal(switcher.extractTierHintFromSecret(blobEnterprise), 'Google AI Ultra');
});

test('parseUserPlanStatus distinguishes Google AI Ultra 5x vs 20x and keeps enterprise Ultra generic', () => {
  const { parseUserPlanStatus } = require(path.join(ROOT, 'payload', 'dist', 'meter-core.js'));

  const res5x = parseUserPlanStatus({
    userStatus: {
      email: 'five@example.com',
      userTier: {
        id: 'g1-ultra-lite-tier',
        name: 'Google AI Ultra',
        description: 'Google AI Ultra',
        upgradeSubscriptionUri: 'https://antigravity.google/g1-upgrade',
        upgradeSubscriptionText: 'You can upgrade to a higher Google AI Ultra plan to receive the highest rate limits.',
      },
    },
  });
  assert.equal(res5x.tierKey, 'ultra');
  assert.equal(res5x.tierName, 'Google AI Ultra 5x');

  const res20x = parseUserPlanStatus({
    userStatus: {
      email: 'twenty@example.com',
      userTier: {
        id: 'g1-ultra-tier',
        name: 'Google AI Ultra',
        description: 'Google AI Ultra',
        upgradeSubscriptionText: 'You are subscribed to the best Google AI plan.',
      },
    },
  });
  assert.equal(res20x.tierKey, 'ultra');
  assert.equal(res20x.tierName, 'Google AI Ultra 20x');

  const resEnterprise = parseUserPlanStatus({
    userStatus: {
      email: 'corp@example.com',
      userTier: {
        id: 'gcp-ge-ultra-tier',
        name: 'Google AI Ultra',
      },
    },
  });
  assert.equal(resEnterprise.tierKey, 'ultra');
  assert.equal(resEnterprise.tierName, 'Google AI Ultra');

  const resFallbackUpgrade = parseUserPlanStatus({
    userStatus: {
      email: 'fallback@example.com',
      userTier: {
        id: 'g1-ultra-custom',
        name: 'Google AI Ultra',
        upgradeSubscriptionUri: 'https://antigravity.google/g1-upgrade',
        upgradeSubscriptionText: 'You can upgrade to a higher Google AI Ultra plan.',
      },
    },
  });
  assert.equal(resFallbackUpgrade.tierName, 'Google AI Ultra 5x');

  const resExplicitParen = parseUserPlanStatus({
    userStatus: {
      email: 'paren@example.com',
      userTier: {
        id: 'unknown-ultra',
        name: 'Google AI Ultra (5x)',
      },
    },
  });
  assert.equal(resExplicitParen.tierName, 'Google AI Ultra 5x');
});

test('getAccountsStatus auto-updates stored generic Ultra tierName to live 5x/20x without reading -w', () => {
  withTempDir((tmp) => {
    const secret5x = encodeGoKeyringSecret({ id_token_email: 'five@example.com', user_tier: 'g1-ultra-lite-tier' });
    const kc = makeMockKeychain({
      'gemini::antigravity': secret5x,
      'antigravity-hakimi-accounts::five@example.com': secret5x,
    });
    switcher.saveProfilesRegistry(
      {
        profiles: [
          { id: 'five@example.com', email: 'five@example.com', tierName: 'Google AI Ultra', tokenFingerprint: switcher.computeTokenFingerprint(secret5x) },
        ],
      },
      { stateDir: tmp }
    );

    const status = switcher.getAccountsStatus({
      platform: 'darwin',
      stateDir: tmp,
      keychain: kc,
      currentEmail: 'five@example.com',
      currentTierName: 'Google AI Ultra 5x',
      detectAgyCliImpl: () => [],
    });
    assert.equal(status.ok, true);
    assert.equal(status.activeTierName, 'Google AI Ultra 5x');
    assert.equal(status.profiles[0].tierName, 'Google AI Ultra 5x');
    assert.equal(kc.calls.get.length, 0);

    const reloaded = switcher.loadProfilesRegistry({ stateDir: tmp });
    assert.equal(reloaded.profiles[0].tierName, 'Google AI Ultra 5x');
  });
});

test('detectRunningAgyCliProcesses matches agy CLI and agy language_server without false positives', () => {
  const fakePs = [
    '  101 /Applications/哈基米.app/Contents/MacOS/Antigravity',
    '  102 /Applications/哈基米.app/Contents/Resources/bin/language_server --standalone --app_data_dir antigravity',
    '  201 /Users/dev/.local/bin/agy chat --prompt hello',
    '  202 /Users/dev/.local/share/antigravity/language_server --app_data_dir antigravity-cli --port 0',
    '  303 /bin/zsh -c echo agy-notes.txt',
    '  404 agy',
  ].join('\n');

  const hits = coldHelper.detectRunningAgyCliProcesses({
    execFileSync: () => fakePs,
    excludePids: [],
  });
  const pids = hits.map((h) => h.pid).sort((a, b) => a - b);
  assert.deepEqual(pids, [201, 202, 404]);
});

test('cleanupAccountLocalResidue removes only account-bound residue while preserving installation_id and shared chats', () => {
  withTempDir((tmp) => {
    const homeDir = path.join(tmp, 'home');
    const geminiDir = path.join(homeDir, '.gemini');
    const agDir = path.join(geminiDir, 'antigravity');
    const userDataDir = path.join(homeDir, 'Library', 'Application Support', 'Antigravity');

    fs.mkdirSync(path.join(geminiDir, 'cache'), { recursive: true });
    fs.mkdirSync(path.join(agDir, 'conversations'), { recursive: true });
    fs.mkdirSync(path.join(agDir, 'brain'), { recursive: true });
    fs.mkdirSync(userDataDir, { recursive: true });

    // Residue files that MUST be removed
    const fallbackTok = path.join(geminiDir, 'jetski-standalone-oauth-token');
    const markerFile = path.join(geminiDir, 'cache', 'antigravity-keyring-unavailable');
    const scopeFile = path.join(userDataDir, 'credential-user-scope');
    fs.writeFileSync(fallbackTok, '{"token":"old"}');
    fs.writeFileSync(markerFile, '1');
    fs.writeFileSync(scopeFile, '0123456789abcdef\n');

    // Files that MUST stay untouched
    const installIdPath = path.join(agDir, 'installation_id');
    const statePbtxtPath = path.join(agDir, 'antigravity_state.pbtxt');
    const convDbPath = path.join(agDir, 'conversation_summaries.db');
    const convPbPath = path.join(agDir, 'conversations', 'shared-1.pb');
    fs.writeFileSync(installIdPath, '11111111-2222-3333-4444-555555555555');
    fs.writeFileSync(statePbtxtPath, 'installation_uuid: "aaaa-bbbb"\n');
    fs.writeFileSync(convDbPath, 'sqlite-placeholder');
    fs.writeFileSync(convPbPath, 'shared-chat-data');

    // app_storage.json: strip ONLY account-bound keys, keep layout/pins/history
    const appStoragePath = path.join(userDataDir, 'app_storage.json');
    fs.writeFileSync(
      appStoragePath,
      JSON.stringify({
        'agy.onboarding.lastLoginUsername': 'alice@work.com',
        'agy.onboarding.lastLoginIsGcpTos': 'false',
        'enable-wcv-three-layer-stack': 'true',
        'enable-remote-control-hub-browser-stream': 'false',
        'enable-agy-hub-cua-macos': 'true',
        pinned_conversations_order: ['c1', 'c2'],
        'jetski.browser.history.persist:hub-browser-deadbeef': ['https://example.com'],
      })
    );

    const res = coldHelper.cleanupAccountLocalResidue({ homeDir, userDataDir, geminiDir });
    assert.equal(res.removedFallbackToken, true);
    assert.equal(res.removedKeyringMarker, true);
    assert.equal(res.removedCredentialScope, true);
    assert.deepEqual(res.clearedAppStorageKeys.sort(), [...coldHelper.ACCOUNT_SCOPED_APP_STORAGE_KEYS].sort());

    assert.equal(fs.existsSync(fallbackTok), false);
    assert.equal(fs.existsSync(markerFile), false);
    assert.equal(fs.existsSync(scopeFile), false);

    // Preserved files remain byte-identical
    assert.equal(fs.readFileSync(installIdPath, 'utf8'), '11111111-2222-3333-4444-555555555555');
    assert.equal(fs.readFileSync(statePbtxtPath, 'utf8'), 'installation_uuid: "aaaa-bbbb"\n');
    assert.equal(fs.readFileSync(convDbPath, 'utf8'), 'sqlite-placeholder');
    assert.equal(fs.readFileSync(convPbPath, 'utf8'), 'shared-chat-data');

    const storageAfter = JSON.parse(fs.readFileSync(appStoragePath, 'utf8'));
    assert.deepEqual(storageAfter, {
      pinned_conversations_order: ['c1', 'c2'],
      'jetski.browser.history.persist:hub-browser-deadbeef': ['https://example.com'],
    });
  });
});

test('startColdSwitchAccount blocks when agy CLI is running and never touches Keychain or spawns helper', () => {
  withTempDir((tmp) => {
    const secretA = encodeGoKeyringSecret({ id_token_email: 'a@test.com', refresh_token: 'rt-a' });
    const secretB = encodeGoKeyringSecret({ id_token_email: 'b@test.com', refresh_token: 'rt-b' });
    const kc = makeMockKeychain({
      'gemini::antigravity': secretA,
      'antigravity-hakimi-accounts::b@test.com': secretB,
    });
    switcher.saveProfilesRegistry(
      { profiles: [{ id: 'b@test.com', email: 'b@test.com', tokenFingerprint: switcher.computeTokenFingerprint(secretB) }] },
      { stateDir: tmp }
    );

    let spawned = false;
    const res = switcher.startColdSwitchAccount(
      { targetId: 'b@test.com', currentEmail: 'a@test.com' },
      {
        platform: 'darwin',
        stateDir: tmp,
        keychain: kc,
        appBundlePath: '/Applications/哈基米.app',
        detectAgyCliImpl: () => [{ pid: 9999, command: '/Users/dev/.local/bin/agy' }],
        spawnImpl: () => {
          spawned = true;
          return { pid: 1234, unref() {} };
        },
      }
    );

    assert.equal(res.ok, false);
    assert.equal(res.code, 'AGY_CLI_RUNNING');
    assert.deepEqual(res.agyCliPids, [9999]);
    assert.equal(spawned, false);
    assert.equal(kc.calls.set.length, 0);
  });
});

test('startColdSwitchAccount stages helper & zero-secret job JSON and spawns detached child', () => {
  withTempDir((tmp) => {
    const secretA = encodeGoKeyringSecret({ id_token_email: 'a@test.com', refresh_token: 'SUPER_SECRET_A' });
    const secretB = encodeGoKeyringSecret({ id_token_email: 'b@test.com', refresh_token: 'SUPER_SECRET_B' });
    const kc = makeMockKeychain({
      'gemini::antigravity': secretA,
      'antigravity-hakimi-accounts::b@test.com': secretB,
    });
    switcher.saveProfilesRegistry(
      { profiles: [{ id: 'b@test.com', email: 'b@test.com', label: 'Backup', tokenFingerprint: switcher.computeTokenFingerprint(secretB) }] },
      { stateDir: tmp }
    );

    let capturedSpawn = null;
    let unrefCalled = false;
    const res = switcher.startColdSwitchAccount(
      { targetId: 'b@test.com', currentEmail: 'a@test.com' },
      {
        platform: 'darwin',
        stateDir: tmp,
        keychain: kc,
        appBundlePath: '/Applications/哈基米.app',
        nodeBin: '/opt/homebrew/bin/node',
        detectAgyCliImpl: () => [],
        spawnImpl: (bin, args, opts) => {
          capturedSpawn = { bin, args, opts };
          return {
            pid: 43210,
            unref() { unrefCalled = true; },
          };
        },
      }
    );

    assert.equal(res.ok, true);
    assert.equal(res.coldSwitching, true);
    assert.equal(res.helperPid, 43210);
    assert.equal(unrefCalled, true);
    assert.equal(capturedSpawn.bin, '/opt/homebrew/bin/node');
    assert.equal(capturedSpawn.opts.detached, true);
    assert.equal(capturedSpawn.args[1], '--job');

    const stagedHelper = capturedSpawn.args[0];
    const jobFile = capturedSpawn.args[2];
    assert.ok(fs.existsSync(stagedHelper));
    assert.ok(fs.existsSync(jobFile));

    const jobRaw = fs.readFileSync(jobFile, 'utf8');
    assert.equal(jobRaw.includes('SUPER_SECRET'), false, 'job JSON must never contain OAuth secrets');
    const jobObj = JSON.parse(jobRaw);
    assert.equal(jobObj.action, 'switch');
    assert.equal(jobObj.targetId, 'b@test.com');
  });
});

test('executeColdAccountJob enforces exit barrier, swaps Keychain with auto-backup, cleans residue, and relaunches cleanly', () => {
  withTempDir((tmp) => {
    const homeDir = path.join(tmp, 'home');
    const geminiDir = path.join(homeDir, '.gemini');
    const agDir = path.join(geminiDir, 'antigravity');
    const userDataDir = path.join(homeDir, 'Library', 'Application Support', 'Antigravity');
    const stateDir = path.join(tmp, 'state');

    fs.mkdirSync(path.join(geminiDir, 'cache'), { recursive: true });
    fs.mkdirSync(agDir, { recursive: true });
    fs.mkdirSync(userDataDir, { recursive: true });
    fs.writeFileSync(path.join(agDir, 'installation_id'), 'keep-this-uuid');
    fs.writeFileSync(path.join(userDataDir, 'credential-user-scope'), 'oldscope12345678\n');
    fs.writeFileSync(path.join(geminiDir, 'jetski-standalone-oauth-token'), 'stale-file-token');
    fs.writeFileSync(
      path.join(userDataDir, 'app_storage.json'),
      JSON.stringify({ 'agy.onboarding.lastLoginUsername': 'unsaved@work.com', keepMe: 1 })
    );

    // Create a stale SingletonLock pointing to dead PID 999991
    fs.symlinkSync('macbook-999991', path.join(userDataDir, 'SingletonLock'));

    const secretUnsaved = encodeGoKeyringSecret({ id_token_email: 'unsaved@work.com', refresh_token: 'RT_UNSAVED_SECRET' });
    const secretTarget = encodeGoKeyringSecret({ id_token_email: 'target@home.com', refresh_token: 'RT_TARGET_SECRET' });
    const kc = makeMockKeychain({
      'gemini::antigravity': secretUnsaved,
      'antigravity-hakimi-accounts::target@home.com': secretTarget,
    });
    switcher.saveProfilesRegistry(
      { profiles: [{ id: 'target@home.com', email: 'target@home.com', label: 'Home', tokenFingerprint: switcher.computeTokenFingerprint(secretTarget) }] },
      { stateDir }
    );

    // Simulate 1 living main PID exiting after first poll
    let pollCount = 0;
    const events = [];
    const relaunches = [];

    const res = coldHelper.executeColdAccountJob(
      {
        action: 'switch',
        targetId: 'target@home.com',
        currentEmail: 'unsaved@work.com',
        currentTierName: 'Pro',
        appBundlePath: '/Applications/哈基米.app',
        stateDir,
        userDataDir,
        geminiDir,
        homeDir,
      },
      {
        keychain: kc,
        pollIntervalMs: 10,
        initialGraceMs: 30,
        sleepImpl: () => {},
        findPidsImpl: (mode) => {
          pollCount += 1;
          if (pollCount <= 2) return mode === 'main' ? [5555] : [5555, 5556];
          return [];
        },
        killImpl: (pid, sig) => {
          if (sig === 0 && pid === 999991) {
            const e = new Error('ESRCH');
            e.code = 'ESRCH';
            throw e;
          }
          events.push({ pid, sig });
        },
        detectAgyCliImpl: () => [],
        env: {
          PATH: '/usr/bin:/bin',
          ELECTRON_RUN_AS_NODE: '1',
          ELECTRON_NO_ASAR: '1',
          NODE_OPTIONS: '--inspect',
          DEV_URL: 'http://localhost:3000',
        },
        spawnImpl: (bin, args, opts) => {
          relaunches.push({ bin, args, opts });
          return { pid: 7777, unref() {} };
        },
      }
    );

    assert.equal(res.ok, true);
    assert.equal(res.autoSavedPrevious, true);
    assert.equal(res.switchedTo.id, 'target@home.com');
    assert.equal(res.relaunched, true);

    // Active slot now holds target secret; outgoing unsaved account backed up in Vault!
    assert.equal(kc.get('gemini', 'antigravity'), secretTarget);
    assert.equal(kc.get('antigravity-hakimi-accounts', 'unsaved@work.com'), secretUnsaved);

    // Residue cleaned, SingletonLock cleaned, installation_id preserved, onboarding synced to target
    assert.equal(fs.existsSync(path.join(userDataDir, 'credential-user-scope')), false);
    assert.equal(fs.existsSync(path.join(geminiDir, 'jetski-standalone-oauth-token')), false);
    assert.equal(fs.existsSync(path.join(userDataDir, 'SingletonLock')), false);
    assert.equal(fs.readFileSync(path.join(agDir, 'installation_id'), 'utf8'), 'keep-this-uuid');
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(userDataDir, 'app_storage.json'), 'utf8')), {
      keepMe: 1,
      'agy.onboarding.lastLoginUsername': 'target@home.com',
      'agy.onboarding.lastLoginIsGcpTos': 'false',
    });

    // Relaunch invoked /usr/bin/open -n with stripped Electron env vars
    assert.equal(relaunches.length, 1);
    assert.equal(relaunches[0].bin, '/usr/bin/open');
    assert.deepEqual(relaunches[0].args, ['-n', '/Applications/哈基米.app']);
    for (const k of coldHelper.RELAUNCH_STRIP_ENV_KEYS) {
      assert.equal(Object.prototype.hasOwnProperty.call(relaunches[0].opts.env, k), false, `env should strip ${k}`);
    }

    // Zero plaintext tokens anywhere on disk under stateDir
    const walk = (d) => {
      for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
        const full = path.join(d, entry.name);
        if (entry.isDirectory()) walk(full);
        else {
          const content = fs.readFileSync(full, 'utf8');
          assert.equal(content.includes('RT_UNSAVED_SECRET'), false);
          assert.equal(content.includes('RT_TARGET_SECRET'), false);
          assert.equal(content.includes('go-keyring-base64:'), false);
        }
      }
    };
    walk(stateDir);
  });
});

test('executeColdAccountJob prepare-add backs up outgoing slot without touching Vault and clears active slot', () => {
  withTempDir((tmp) => {
    const stateDir = path.join(tmp, 'state');
    const homeDir = path.join(tmp, 'home');
    const userDataDir = path.join(homeDir, 'Library', 'Application Support', 'Antigravity');
    const geminiDir = path.join(homeDir, '.gemini');
    fs.mkdirSync(userDataDir, { recursive: true });
    fs.mkdirSync(geminiDir, { recursive: true });

    const secretA = encodeGoKeyringSecret({ id_token_email: 'a@work.com', refresh_token: 'RT_KEEP_ALIVE' });
    const kc = makeMockKeychain({ 'gemini::antigravity': secretA });
    const relaunches = [];

    const res = coldHelper.executeColdAccountJob(
      {
        action: 'prepare-add',
        currentEmail: 'a@work.com',
        appBundlePath: '/Applications/哈基米.app',
        stateDir,
        userDataDir,
        geminiDir,
        homeDir,
      },
      {
        keychain: kc,
        skipStop: true,
        sleepImpl: () => {},
        detectAgyCliImpl: () => [],
        spawnImpl: (bin, args) => {
          relaunches.push({ bin, args });
          return { pid: 8888, unref() {} };
        },
      }
    );

    assert.equal(res.ok, true);
    assert.equal(res.clearedActive, true);
    assert.equal(res.backedUpProfile.id, 'a@work.com');
    assert.equal(kc.get('gemini', 'antigravity'), null);
    assert.equal(kc.get('antigravity-hakimi-accounts', 'a@work.com'), secretA);
    assert.equal(relaunches.length, 1);
  });
});

test('official Antigravity.app bundle is strictly rejected by cold-switch guard', () => {
  withTempDir((tmp) => {
    const res = coldHelper.executeColdAccountJob(
      {
        action: 'prepare-add',
        appBundlePath: '/Applications/Antigravity.app',
        stateDir: tmp,
      },
      { skipStop: true, relaunch: false }
    );
    assert.equal(res.ok, false);
    assert.match(res.error, /禁止|官方/);
  });
});

test('saveCurrentAccount, renameAccount, removeAccount and non-macOS degradation behave cleanly', () => {
  withTempDir((tmp) => {
    const secretA = encodeGoKeyringSecret({ id_token_email: 'a@work.com', refresh_token: 'rt-a-1' });
    const kc = makeMockKeychain({ 'gemini::antigravity': secretA });

    const linuxRes = switcher.getAccountsStatus({ platform: 'linux', stateDir: tmp, keychain: kc });
    assert.equal(linuxRes.ok, false);
    assert.equal(linuxRes.supported, false);

    const saved = switcher.saveCurrentAccount(
      { email: 'a@work.com', label: '主力 Pro', tierName: 'Pro' },
      { platform: 'darwin', stateDir: tmp, keychain: kc, detectAgyCliImpl: () => [] }
    );
    assert.equal(saved.ok, true);
    assert.equal(saved.profile.label, '主力 Pro');

    const renamed = switcher.renameAccount(
      { targetId: 'a@work.com', label: '工作号 Pro' },
      { platform: 'darwin', stateDir: tmp, keychain: kc, detectAgyCliImpl: () => [] }
    );
    assert.equal(renamed.ok, true);
    assert.equal(renamed.profile.label, '工作号 Pro');

    const removed = switcher.removeAccount(
      { targetId: 'a@work.com' },
      { platform: 'darwin', stateDir: tmp, keychain: kc, detectAgyCliImpl: () => [] }
    );
    assert.equal(removed.ok, true);
    assert.equal(kc.get('antigravity-hakimi-accounts', 'a@work.com'), null);
    // Active login slot untouched when removing Vault snapshot
    assert.equal(kc.get('gemini', 'antigravity'), secretA);
  });
});

test('preload bridge and ASAR PAYLOAD_FILES include cold account switcher modules', () => {
  const preloadCode = modularInstaller.generateMeterPreloadCode();
  for (const fn of [
    'getAccountsStatus',
    'saveCurrentAccount',
    'switchAccount',
    'prepareAddAccount',
    'renameAccount',
    'removeAccount',
  ]) {
    assert.ok(preloadCode.includes(`${fn}:`), `preload missing ${fn}`);
  }
  assert.ok(PAYLOAD_FILES.includes('meter-account-cold-helper.js'));
  assert.ok(PAYLOAD_FILES.includes('meter-account-switcher.js'));
});

test('executeColdAccountJob suppresses relaunch when main process fails to exit, but relaunches on post-exit Keychain failure', () => {
  withTempDir((tmp) => {
    const stateDir = path.join(tmp, 'state');
    const relaunchesA = [];
    const resA = coldHelper.executeColdAccountJob(
      {
        action: 'prepare-add',
        appBundlePath: '/Applications/哈基米.app',
        stateDir,
      },
      {
        pollIntervalMs: 5,
        initialGraceMs: 10,
        mainTermMs: 10,
        allTermMs: 10,
        killWaitMs: 10,
        sleepImpl: () => {},
        findPidsImpl: () => [91001],
        killImpl: () => {},
        spawnImpl: (bin, args) => {
          relaunchesA.push({ bin, args });
          return { pid: 1, unref() {} };
        },
      }
    );
    assert.equal(resA.ok, false);
    assert.match(resA.error, /退出超时/);
    assert.equal(relaunchesA.length, 0, 'must not spawn duplicate app while main PID still alive');

    const stateDirB = path.join(tmp, 'state-b');
    const relaunchesB = [];
    const lockedKc = {
      has() { throw new Error('macOS 钥匙串当前已锁定'); },
      get() { throw new Error('macOS 钥匙串当前已锁定'); },
      set() { throw new Error('macOS 钥匙串当前已锁定'); },
      delete() { throw new Error('macOS 钥匙串当前已锁定'); },
    };
    const resB = coldHelper.executeColdAccountJob(
      {
        action: 'prepare-add',
        appBundlePath: '/Applications/哈基米.app',
        stateDir: stateDirB,
      },
      {
        keychain: lockedKc,
        skipStop: true,
        sleepImpl: () => {},
        detectAgyCliImpl: () => [],
        spawnImpl: (bin, args) => {
          relaunchesB.push({ bin, args });
          return { pid: 2, unref() {} };
        },
      }
    );
    assert.equal(resB.ok, false);
    assert.match(resB.error, /钥匙串当前已锁定/);
    assert.equal(resB.relaunched, true);
    assert.equal(relaunchesB.length, 1, 'must relaunch app after post-exit Keychain error so user sees error');
  });
});

test('staged meter-account-cold-helper.js runs standalone outside repo with zero relative dependencies', () => {
  const { spawnSync } = require('child_process');
  withTempDir((tmp) => {
    const copiedHelper = path.join(tmp, 'cold-switch-helper.js');
    fs.copyFileSync(path.join(ROOT, 'payload', 'dist', 'meter-account-cold-helper.js'), copiedHelper);
    const stateDir = path.join(tmp, 'state');
    const jobFile = path.join(tmp, 'job.json');
    fs.writeFileSync(
      jobFile,
      JSON.stringify({
        action: 'noop-test-action',
        stateDir,
        appBundlePath: '',
      })
    );
    const run = spawnSync(process.execPath, [copiedHelper, '--job', jobFile], {
      encoding: 'utf8',
      timeout: 5000,
    });
    assert.equal(run.status, 1);
    assert.equal(fs.existsSync(jobFile), false, 'helper must delete transient job file after reading');
    const resultPath = path.join(stateDir, 'runtime', 'cold-switch-last-result.json');
    assert.ok(fs.existsSync(resultPath));
    const parsed = JSON.parse(fs.readFileSync(resultPath, 'utf8'));
    assert.equal(parsed.ok, false);
    assert.match(parsed.error, /未知的冷切换动作/);
  });
});

test('cold switch captures exact onboarding casing/isGcpTos and restores target onboarding to avoid modal re-prompt', () => {
  withTempDir((tmp) => {
    const homeDir = path.join(tmp, 'home');
    const geminiDir = path.join(homeDir, '.gemini');
    const userDataDir = path.join(homeDir, 'Library', 'Application Support', 'Antigravity');
    const stateDir = path.join(tmp, 'state');
    fs.mkdirSync(userDataDir, { recursive: true });
    fs.mkdirSync(geminiDir, { recursive: true });

    const appStoragePath = path.join(userDataDir, 'app_storage.json');
    fs.writeFileSync(
      appStoragePath,
      JSON.stringify({
        'agy.onboarding.lastLoginUsername': 'Alice.Work@Corp.COM',
        'agy.onboarding.lastLoginIsGcpTos': 'true',
        'jetski.onboarding.lastLoginUsername': 'stale@legacy.com',
        'enable-wcv-three-layer-stack': 'true',
        keepLayout: 'ok',
      })
    );

    const secretA = encodeGoKeyringSecret({
      id_token_email: 'Alice.Work@Corp.COM',
      auth_method: 'gcp',
      refresh_token: 'rt-a-gcp',
    });
    const secretB = encodeGoKeyringSecret({
      id_token_email: 'Bob.Home@Gmail.com',
      auth_method: 'consumer',
      refresh_token: 'rt-b-consumer',
    });
    const kc = makeMockKeychain({
      'gemini::antigravity': secretA,
      'antigravity-hakimi-accounts::alice.work@corp.com': secretA,
      'antigravity-hakimi-accounts::bob.home@gmail.com': secretB,
    });
    switcher.saveProfilesRegistry(
      {
        profiles: [
          { id: 'alice.work@corp.com', email: 'alice.work@corp.com', tokenFingerprint: switcher.computeTokenFingerprint(secretA) },
          { id: 'bob.home@gmail.com', email: 'bob.home@gmail.com', tokenFingerprint: switcher.computeTokenFingerprint(secretB) },
        ],
      },
      { stateDir }
    );

    // Switch A -> B: captures A's exact casing + isGcpTos='true', sets B's exact casing + isGcpTos='false'
    const res1 = coldHelper.executeColdAccountJob(
      {
        action: 'switch',
        targetId: 'bob.home@gmail.com',
        currentEmail: 'Alice.Work@Corp.COM',
        appBundlePath: '/Applications/哈基米.app',
        stateDir,
        userDataDir,
        geminiDir,
        homeDir,
      },
      { keychain: kc, skipStop: true, relaunch: false, detectAgyCliImpl: () => [] }
    );
    assert.equal(res1.ok, true);
    const storageAfterB = JSON.parse(fs.readFileSync(appStoragePath, 'utf8'));
    assert.deepEqual(storageAfterB, {
      keepLayout: 'ok',
      'agy.onboarding.lastLoginUsername': 'Bob.Home@Gmail.com',
      'agy.onboarding.lastLoginIsGcpTos': 'false',
    });

    // Switch B -> A: restores A's captured exact casing + isGcpTos='true'
    const res2 = coldHelper.executeColdAccountJob(
      {
        action: 'switch',
        targetId: 'alice.work@corp.com',
        currentEmail: 'Bob.Home@Gmail.com',
        appBundlePath: '/Applications/哈基米.app',
        stateDir,
        userDataDir,
        geminiDir,
        homeDir,
      },
      { keychain: kc, skipStop: true, relaunch: false, detectAgyCliImpl: () => [] }
    );
    assert.equal(res2.ok, true);
    const storageAfterA = JSON.parse(fs.readFileSync(appStoragePath, 'utf8'));
    assert.deepEqual(storageAfterA, {
      keepLayout: 'ok',
      'agy.onboarding.lastLoginUsername': 'Alice.Work@Corp.COM',
      'agy.onboarding.lastLoginIsGcpTos': 'true',
    });
  });
});

test('upsertProfileWithSecret prioritizes token id_token_email over stale meta.email and avoids corrupted fingerprint binding', () => {
  const secretBob = encodeGoKeyringSecret({
    id_token_email: 'Bob@Example.COM',
    user_tier: 'g1-ultra-lite-tier',
    tier_display_name: 'Google AI Ultra',
    auth_method: 'consumer',
    refresh_token: 'rt-bob-truth',
  });
  const secretAliceOld = encodeGoKeyringSecret({
    id_token_email: 'alice@example.com',
    refresh_token: 'rt-alice-valid',
  });
  const kc = makeMockKeychain({
    'antigravity-hakimi-accounts::alice@example.com': secretAliceOld,
  });
  const registry = {
    version: '1.0.0',
    updatedAt: '',
    profiles: [
      {
        id: 'alice@example.com',
        email: 'alice@example.com',
        label: 'AliceWork',
        tierName: 'Google AI Ultra 20x',
        // Simulate a legacy corrupted fingerprint colliding with Bob's token
        tokenFingerprint: coldHelper.computeTokenFingerprint(secretBob),
        onboardingUsername: 'alice@example.com',
        onboardingIsGcpTos: 'false',
      },
    ],
  };

  const entry = coldHelper.upsertProfileWithSecret(registry, kc, secretBob, {
    email: 'alice@example.com',
    label: 'AliceWork',
    tierName: 'Google AI Ultra 20x',
    onboardingUsername: 'alice@example.com',
    onboardingIsGcpTos: 'true',
  });

  // Must bind strictly to token's own id_token_email, never overwriting Alice's Vault slot or metadata
  assert.equal(entry.id, 'bob@example.com');
  assert.equal(entry.email, 'bob@example.com');
  assert.equal(entry.label, '');
  assert.equal(entry.tierName, 'Google AI Ultra 5x');
  assert.equal(entry.onboardingUsername, 'Bob@Example.COM');
  assert.equal(entry.onboardingIsGcpTos, 'false');
  assert.equal(kc.get('antigravity-hakimi-accounts', 'bob@example.com'), secretBob);
  assert.equal(kc.get('antigravity-hakimi-accounts', 'alice@example.com'), secretAliceOld);
});

test('saveCurrentAccount blocks saving when UI email conflicts with active Keychain id_token_email', () => {
  withTempDir((tmp) => {
    const secretBob = encodeGoKeyringSecret({
      id_token_email: 'bob@gmail.com',
      refresh_token: 'rt-bob-active',
    });
    const kc = makeMockKeychain({
      'gemini::antigravity': secretBob,
    });

    const res = switcher.saveCurrentAccount(
      { email: 'alice@gmail.com', tierName: 'Google AI Ultra 20x' },
      { platform: 'darwin', stateDir: tmp, keychain: kc, detectAgyCliImpl: () => [] }
    );

    assert.equal(res.ok, false);
    assert.equal(res.code, 'ACTIVE_IDENTITY_MISMATCH');
    assert.equal(res.uiEmail, 'alice@gmail.com');
    assert.equal(res.activeKeychainEmail, 'bob@gmail.com');
    assert.match(res.error, /alice@gmail\.com/);
    assert.match(res.error, /bob@gmail\.com/);
    assert.equal(kc.calls.set.length, 0);
    assert.equal(switcher.loadProfilesRegistry({ stateDir: tmp }).profiles.length, 0);
  });
});

test('executeColdAccountJob switch aborts cleanly when target Vault snapshot id_token_email mismatches profile', () => {
  withTempDir((tmp) => {
    const homeDir = path.join(tmp, 'home');
    const geminiDir = path.join(homeDir, '.gemini');
    const userDataDir = path.join(homeDir, 'Library', 'Application Support', 'Antigravity');
    const stateDir = path.join(tmp, 'state');
    fs.mkdirSync(userDataDir, { recursive: true });
    fs.mkdirSync(geminiDir, { recursive: true });

    const appStoragePath = path.join(userDataDir, 'app_storage.json');
    fs.writeFileSync(
      appStoragePath,
      JSON.stringify({ 'agy.onboarding.lastLoginUsername': 'charlie@gmail.com' })
    );

    const secretCharlie = encodeGoKeyringSecret({ id_token_email: 'charlie@gmail.com', refresh_token: 'rt-c' });
    const secretBobPoisoned = encodeGoKeyringSecret({ id_token_email: 'bob@gmail.com', refresh_token: 'rt-b' });
    const kc = makeMockKeychain({
      'gemini::antigravity': secretCharlie,
      // Poisoned Vault snapshot: stored under alice@gmail.com, but token actually belongs to bob@gmail.com
      'antigravity-hakimi-accounts::alice@gmail.com': secretBobPoisoned,
    });
    switcher.saveProfilesRegistry(
      {
        profiles: [
          {
            id: 'alice@gmail.com',
            email: 'alice@gmail.com',
            tierName: 'Google AI Ultra 20x',
            tokenFingerprint: coldHelper.computeTokenFingerprint(secretBobPoisoned),
          },
        ],
      },
      { stateDir }
    );

    const relaunches = [];
    const res = coldHelper.executeColdAccountJob(
      {
        action: 'switch',
        targetId: 'alice@gmail.com',
        currentEmail: 'charlie@gmail.com',
        appBundlePath: '/Applications/哈基米.app',
        stateDir,
        userDataDir,
        geminiDir,
        homeDir,
      },
      {
        keychain: kc,
        skipStop: true,
        sleepImpl: () => {},
        detectAgyCliImpl: () => [],
        spawnImpl: (bin, args) => {
          relaunches.push({ bin, args });
          return { pid: 9001, unref() {} };
        },
      }
    );

    assert.equal(res.ok, false);
    assert.equal(res.code, 'VAULT_IDENTITY_MISMATCH');
    assert.equal(res.expectedEmail, 'alice@gmail.com');
    assert.equal(res.actualEmail, 'bob@gmail.com');
    assert.match(res.error, /alice@gmail\.com/);
    assert.match(res.error, /bob@gmail\.com/);
    // Active slot and app_storage must stay untouched, while app still relaunches so user sees error
    assert.equal(kc.get('gemini', 'antigravity'), secretCharlie);
    assert.deepEqual(JSON.parse(fs.readFileSync(appStoragePath, 'utf8')), {
      'agy.onboarding.lastLoginUsername': 'charlie@gmail.com',
    });
    assert.equal(res.relaunched, true);
    assert.equal(relaunches.length, 1);

    const lastRes = JSON.parse(fs.readFileSync(coldHelper.getColdResultPath({ stateDir }), 'utf8'));
    assert.equal(lastRes.ok, false);
    assert.equal(lastRes.code, 'VAULT_IDENTITY_MISMATCH');
  });
});

test('executeColdAccountJob switch and prepare-add use active token id_token_email when job.currentEmail is stale', () => {
  withTempDir((tmp) => {
    const homeDir = path.join(tmp, 'home');
    const geminiDir = path.join(homeDir, '.gemini');
    const userDataDir = path.join(homeDir, 'Library', 'Application Support', 'Antigravity');
    const stateDir = path.join(tmp, 'state');
    fs.mkdirSync(userDataDir, { recursive: true });
    fs.mkdirSync(geminiDir, { recursive: true });
    fs.writeFileSync(
      path.join(userDataDir, 'app_storage.json'),
      JSON.stringify({ 'agy.onboarding.lastLoginUsername': 'alice@gmail.com', 'agy.onboarding.lastLoginIsGcpTos': 'true' })
    );

    const secretAlice = encodeGoKeyringSecret({ id_token_email: 'alice@gmail.com', refresh_token: 'rt-alice' });
    const secretBob = encodeGoKeyringSecret({ id_token_email: 'bob@gmail.com', user_tier: 'g1-ultra-lite-tier', refresh_token: 'rt-bob' });
    const secretCharlie = encodeGoKeyringSecret({ id_token_email: 'charlie@gmail.com', refresh_token: 'rt-charlie' });

    // 1. switch: active Keychain holds Bob, but stale job.currentEmail says Alice; switching to Charlie
    const kc = makeMockKeychain({
      'gemini::antigravity': secretBob,
      'antigravity-hakimi-accounts::alice@gmail.com': secretAlice,
      'antigravity-hakimi-accounts::charlie@gmail.com': secretCharlie,
    });
    switcher.saveProfilesRegistry(
      {
        profiles: [
          { id: 'alice@gmail.com', email: 'alice@gmail.com', label: 'Alice', tierName: 'Google AI Ultra 20x', tokenFingerprint: coldHelper.computeTokenFingerprint(secretAlice) },
          { id: 'charlie@gmail.com', email: 'charlie@gmail.com', label: 'Charlie', tierName: 'Pro', tokenFingerprint: coldHelper.computeTokenFingerprint(secretCharlie) },
        ],
      },
      { stateDir }
    );

    const switchRes = coldHelper.executeColdAccountJob(
      {
        action: 'switch',
        targetId: 'charlie@gmail.com',
        currentEmail: 'alice@gmail.com',
        currentTierName: 'Google AI Ultra 20x',
        appBundlePath: '/Applications/哈基米.app',
        stateDir,
        userDataDir,
        geminiDir,
        homeDir,
      },
      { keychain: kc, skipStop: true, relaunch: false, detectAgyCliImpl: () => [] }
    );
    assert.equal(switchRes.ok, true);
    assert.equal(switchRes.autoSavedPrevious, true);
    assert.equal(switchRes.previousProfile.id, 'bob@gmail.com');
    assert.equal(switchRes.previousProfile.tierName, 'Google AI Ultra 5x');
    assert.equal(kc.get('antigravity-hakimi-accounts', 'alice@gmail.com'), secretAlice);
    assert.equal(kc.get('antigravity-hakimi-accounts', 'bob@gmail.com'), secretBob);
    assert.equal(kc.get('gemini', 'antigravity'), secretCharlie);

    // 2. prepare-add: active Keychain holds Charlie, stale job.currentEmail says Alice
    const prepRes = coldHelper.executeColdAccountJob(
      {
        action: 'prepare-add',
        currentEmail: 'alice@gmail.com',
        currentTierName: 'Google AI Ultra 20x',
        appBundlePath: '/Applications/哈基米.app',
        stateDir,
        userDataDir,
        geminiDir,
        homeDir,
      },
      { keychain: kc, skipStop: true, relaunch: false, detectAgyCliImpl: () => [] }
    );
    assert.equal(prepRes.ok, true);
    assert.equal(prepRes.backedUpProfile.id, 'charlie@gmail.com');
    assert.equal(prepRes.backedUpProfile.tierName, 'Pro');
    assert.equal(kc.get('antigravity-hakimi-accounts', 'alice@gmail.com'), secretAlice);
    assert.equal(kc.get('antigravity-hakimi-accounts', 'charlie@gmail.com'), secretCharlie);
    assert.equal(kc.get('gemini', 'antigravity'), null);
  });
});

test('getAccountsStatus detects activeIdentityMismatch on fallback -w read without overwriting saved profile tier', () => {
  withTempDir((tmp) => {
    const secretBob = encodeGoKeyringSecret({
      id_token_email: 'bob@gmail.com',
      tier_display_name: 'Pro',
      refresh_token: 'rt-bob-live',
    });
    const kc = makeMockKeychain({
      'gemini::antigravity': secretBob,
      'antigravity-hakimi-accounts::bob@gmail.com': secretBob,
    });
    switcher.saveProfilesRegistry(
      {
        profiles: [
          {
            id: 'bob@gmail.com',
            email: 'bob@gmail.com',
            tierName: 'Pro',
            tokenFingerprint: coldHelper.computeTokenFingerprint(secretBob),
          },
        ],
      },
      { stateDir: tmp }
    );

    const status = switcher.getAccountsStatus({
      platform: 'darwin',
      stateDir: tmp,
      keychain: kc,
      currentEmail: 'alice@gmail.com',
      currentTierName: 'Google AI Ultra 20x',
      detectAgyCliImpl: () => [],
    });

    assert.equal(status.ok, true);
    assert.equal(status.activeIdentityMismatch, true);
    assert.equal(status.uiEmail, 'alice@gmail.com');
    assert.equal(status.activeKeychainEmail, 'bob@gmail.com');
    assert.equal(status.activeEmail, 'bob@gmail.com');
    assert.equal(status.activeProfileId, 'bob@gmail.com');
    assert.equal(status.activeTierName, 'Pro');
    assert.equal(status.profiles[0].tierName, 'Pro');
    assert.equal(switcher.loadProfilesRegistry({ stateDir: tmp }).profiles[0].tierName, 'Pro');
  });
});
