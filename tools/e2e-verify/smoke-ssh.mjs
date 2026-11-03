// Stand-in for the real SSH call during smoke tests (SSH_BIN="node smoke-ssh.mjs").
// Ignores the ssh-style args, waits a moment, reports success.
await new Promise((r) => setTimeout(r, 2000));
console.log('[smoke-ssh] simulated remote command completed (exit 0)');
process.exit(0);