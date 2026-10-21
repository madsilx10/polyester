const { ethers } = require('ethers');
const readline = require('readline');
const fs = require('fs');

// ─── CONFIG ───────────────────────────────────────────────────────────────────
const WALLET_FILE = 'wallet.txt';
const BASE_URL = 'https://api.testnet.polyester.com';
const ORIGIN = 'https://testnet.polyester.com';

const HEADERS_BASE = {
  'accept': '*/*',
  'accept-encoding': 'gzip, deflate, br, zstd',
  'accept-language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7',
  'connect-protocol-version': '1',
  'content-type': 'application/proto',
  'origin': ORIGIN,
  'referer': `${ORIGIN}/`,
  'sec-ch-ua': '"Mises";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
  'sec-ch-ua-mobile': '?1',
  'sec-ch-ua-platform': '"Android"',
  'sec-fetch-dest': 'empty',
  'sec-fetch-mode': 'cors',
  'sec-fetch-site': 'same-site',
  'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
};

// ─── HELPERS ──────────────────────────────────────────────────────────────────
function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function rl() {
  return readline.createInterface({ input: process.stdin, output: process.stdout });
}

function ask(iface, question) {
  return new Promise(resolve => iface.question(question, resolve));
}

function log(wallet, msg) {
  const addr = wallet ? wallet.address.slice(0, 8) + '...' : 'SYSTEM';
  console.log(`[${addr}] ${msg}`);
}

function encodeProtoString(fieldNum, str) {
  const strBytes = Buffer.from(str, 'utf8');
  const tag = (fieldNum << 3) | 2;
  return Buffer.concat([
    encodeVarint(tag),
    encodeVarint(strBytes.length),
    strBytes
  ]);
}

function encodeVarint(value) {
  const bytes = [];
  while (value > 0x7f) {
    bytes.push((value & 0x7f) | 0x80);
    value >>>= 7;
  }
  bytes.push(value & 0x7f);
  return Buffer.from(bytes);
}

// ─── PROTO ENCODE ─────────────────────────────────────────────────────────────
// CreateWalletChallenge payload: field1=walletAddress, field2=nonce(addr2), field3=origin
function encodeCreateChallenge(walletAddress, addr2, origin) {
  const f1 = encodeProtoString(1, walletAddress);
  const f2 = encodeProtoString(2, addr2);
  const f3 = encodeProtoString(3, origin);
  return Buffer.concat([f1, f2, f3]);
}

// LoginWithWallet payload: field1=walletAddress, field2=signature, field3=siweMessage
function encodeLoginWithWallet(walletAddress, signature, siweMessage) {
  const f1 = encodeProtoString(1, walletAddress);
  const f2 = encodeProtoString(2, signature);
  const f3 = encodeProtoString(3, siweMessage);
  return Buffer.concat([f1, f2, f3]);
}

// UpdateProfile payload: field1=twitterUsername
function encodeUpdateProfile(twitterUsername) {
  return encodeProtoString(1, twitterUsername);
}

// ─── API CALLS ────────────────────────────────────────────────────────────────
async function createWalletChallenge(wallet) {
  // From devtools: payload = *{addr}*{addr2}*{origin}
  // addr2 = secondary address (from screenshot looks like another addr or nonce addr)
  // We use wallet address for both
  const payload = encodeCreateChallenge(wallet.address, wallet.address, ORIGIN);

  const res = await fetch(`${BASE_URL}/auth.v1.AuthService/CreateWalletChallenge`, {
    method: 'POST',
    headers: HEADERS_BASE,
    body: payload,
  });

  if (!res.ok) throw new Error(`CreateWalletChallenge failed: ${res.status}`);

  // Response is proto binary, extract SIWE message
  const buf = Buffer.from(await res.arrayBuffer());
  // Parse proto: find string fields
  const siweMsg = extractProtoStrings(buf);
  return siweMsg;
}

async function loginWithWallet(wallet, siweMessage) {
  const signature = await wallet.signMessage(siweMessage);
  const payload = encodeLoginWithWallet(wallet.address, signature, siweMessage);

  const res = await fetch(`${BASE_URL}/auth.v1.AuthService/LoginWithWallet`, {
    method: 'POST',
    headers: HEADERS_BASE,
    body: payload,
  });

  if (!res.ok) throw new Error(`LoginWithWallet failed: ${res.status}`);

  const buf = Buffer.from(await res.arrayBuffer());
  const token = extractProtoStrings(buf);
  return token;
}

async function acceptTerms(token) {
  const res = await fetch(`${BASE_URL}/auth.v1.AuthService/AcceptTerms`, {
    method: 'POST',
    headers: { ...HEADERS_BASE, 'authorization': `Bearer ${token}`, 'content-length': '0' },
    body: Buffer.alloc(0),
  });
  if (!res.ok) throw new Error(`AcceptTerms failed: ${res.status}`);
}

async function claimGeneratedUsername(token) {
  const res = await fetch(`${BASE_URL}/auth.v1.ProfileService/ClaimGeneratedUsername`, {
    method: 'POST',
    headers: { ...HEADERS_BASE, 'authorization': `Bearer ${token}`, 'content-length': '0' },
    body: Buffer.alloc(0),
  });
  if (!res.ok) throw new Error(`ClaimGeneratedUsername failed: ${res.status}`);
}

async function startSocialVerification(token) {
  const res = await fetch(`${BASE_URL}/auth.v1.SocialVerificationService/StartSocialVerification`, {
    method: 'POST',
    headers: { ...HEADERS_BASE, 'authorization': `Bearer ${token}`, 'content-length': '0' },
    body: Buffer.alloc(0),
  });
  if (!res.ok) throw new Error(`StartSocialVerification failed: ${res.status}`);

  const buf = Buffer.from(await res.arrayBuffer());
  // Extract verification code from response
  const code = extractProtoStrings(buf);
  return code;
}

async function getSocialVerification(token) {
  const res = await fetch(`${BASE_URL}/auth.v1.SocialVerificationService/GetSocialVerification`, {
    method: 'POST',
    headers: { ...HEADERS_BASE, 'authorization': `Bearer ${token}`, 'content-length': '2' },
    body: Buffer.from([0x08, 0x01]), // field1=1 (platform=twitter)
  });
  if (!res.ok) throw new Error(`GetSocialVerification failed: ${res.status}`);

  const buf = Buffer.from(await res.arrayBuffer());
  return buf;
}

async function updateProfile(token, twitterUsername) {
  const payload = encodeUpdateProfile(twitterUsername);
  const res = await fetch(`${BASE_URL}/auth.v1.ProfileService/UpdateProfile`, {
    method: 'POST',
    headers: { ...HEADERS_BASE, 'authorization': `Bearer ${token}` },
    body: payload,
  });
  if (!res.ok) throw new Error(`UpdateProfile failed: ${res.status}`);
}

async function claimDailyReward(token) {
  const res = await fetch(`${BASE_URL}/claims.v1.ClaimsService/ClaimDailyReward`, {
    method: 'POST',
    headers: { ...HEADERS_BASE, 'authorization': `Bearer ${token}`, 'content-length': '0' },
    body: Buffer.alloc(0),
  });
  if (!res.ok) throw new Error(`ClaimDailyReward failed: ${res.status}`);
  return res.ok;
}

// ─── PROTO PARSER (simple) ────────────────────────────────────────────────────
function extractProtoStrings(buf) {
  const strings = [];
  let i = 0;
  while (i < buf.length) {
    try {
      let tag = 0, shift = 0;
      while (i < buf.length) {
        const b = buf[i++];
        tag |= (b & 0x7f) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
      }
      const wireType = tag & 0x07;
      if (wireType === 2) {
        let len = 0; shift = 0;
        while (i < buf.length) {
          const b = buf[i++];
          len |= (b & 0x7f) << shift;
          if (!(b & 0x80)) break;
          shift += 7;
        }
        const bytes = buf.slice(i, i + len);
        i += len;
        const str = bytes.toString('utf8');
        // Filter: only keep printable strings that look like tokens/messages
        if (str.length > 10 && /^[\x20-\x7E\n\r]+$/.test(str)) {
          strings.push(str);
        }
      } else if (wireType === 0) {
        while (i < buf.length && (buf[i++] & 0x80));
      } else if (wireType === 5) {
        i += 4;
      } else if (wireType === 1) {
        i += 8;
      } else {
        break;
      }
    } catch {
      break;
    }
  }
  return strings[0] || '';
}

// ─── MAIN FLOW ────────────────────────────────────────────────────────────────
async function processWallet(wallet, twitterUsername, iface) {
  log(wallet, `Mulai proses wallet ${wallet.address}`);

  // Step 1: CreateWalletChallenge
  log(wallet, 'Step 1: CreateWalletChallenge...');
  const siweMsg = await createWalletChallenge(wallet);
  if (!siweMsg) throw new Error('Gagal dapet SIWE message');
  log(wallet, `SIWE message diterima`);

  // Step 2: LoginWithWallet
  log(wallet, 'Step 2: LoginWithWallet...');
  const token = await loginWithWallet(wallet, siweMsg);
  if (!token) throw new Error('Gagal dapet token');
  log(wallet, `Login berhasil, token: ${token.slice(0, 20)}...`);

  // Step 3: AcceptTerms
  log(wallet, 'Step 3: AcceptTerms...');
  await acceptTerms(token);
  log(wallet, 'Terms diterima');

  // Step 4: ClaimGeneratedUsername
  log(wallet, 'Step 4: ClaimGeneratedUsername...');
  await claimGeneratedUsername(token);
  log(wallet, 'Username di-claim');

  // Step 5: StartSocialVerification
  log(wallet, 'Step 5: StartSocialVerification...');
  const verifyCode = await startSocialVerification(token);
  log(wallet, `\n>>> KODE VERIFIKASI: ${verifyCode || '(cek bio platform)'}`);
  log(wallet, `>>> Taruh kode ini di bio X/Twitter lo, lalu tekan Enter`);
  await ask(iface, '');

  // Step 6: UpdateProfile dengan username X
  log(wallet, 'Step 6: UpdateProfile...');
  await updateProfile(token, twitterUsername);
  log(wallet, `Profile diupdate dengan @${twitterUsername}`);

  // Step 7: Poll GetSocialVerification
  log(wallet, 'Step 7: Polling verifikasi X...');
  let verified = false;
  for (let attempt = 1; attempt <= 20; attempt++) {
    log(wallet, `Cek verifikasi attempt ${attempt}/20...`);
    const res = await getSocialVerification(token);
    // Check if verified (proto response non-empty = ada data = verified)
    if (res.length > 5) {
      verified = true;
      log(wallet, 'Verifikasi X berhasil!');
      break;
    }
    await sleep(5000);
  }

  if (!verified) throw new Error('Verifikasi X timeout');

  // Step 8: ClaimDailyReward
  log(wallet, 'Step 8: ClaimDailyReward...');
  await claimDailyReward(token);
  log(wallet, '✅ Daily reward berhasil di-claim!');
}

async function main() {
  // Load wallets
  if (!fs.existsSync(WALLET_FILE)) {
    console.error(`File ${WALLET_FILE} tidak ditemukan!`);
    process.exit(1);
  }

  const privkeys = fs.readFileSync(WALLET_FILE, 'utf8')
    .split('\n')
    .map(l => l.trim())
    .filter(l => l.length > 0);

  if (privkeys.length === 0) {
    console.error('Tidak ada private key di wallet.txt!');
    process.exit(1);
  }

  const wallets = privkeys.map(pk => new ethers.Wallet(pk.startsWith('0x') ? pk : `0x${pk}`));
  console.log(`\n📂 ${wallets.length} wallet ditemukan`);
  wallets.forEach((w, i) => console.log(`  [${i + 1}] ${w.address}`));

  const iface = rl();

  // Pilih mode
  console.log('\nPilih mode:');
  console.log('  [1] 1 akun');
  console.log('  [2] Semua akun');
  console.log('  [3] From X to end');
  const mode = await ask(iface, '\nPilih: ');

  let selectedWallets = [];

  if (mode.trim() === '1') {
    const idx = await ask(iface, `Pilih akun (1-${wallets.length}): `);
    const i = parseInt(idx.trim()) - 1;
    if (i < 0 || i >= wallets.length) {
      console.error('Index tidak valid!');
      iface.close();
      process.exit(1);
    }
    selectedWallets = [wallets[i]];
  } else if (mode.trim() === '2') {
    selectedWallets = wallets;
  } else if (mode.trim() === '3') {
    const from = await ask(iface, `From akun ke- (1-${wallets.length}): `);
    const i = parseInt(from.trim()) - 1;
    if (i < 0 || i >= wallets.length) {
      console.error('Index tidak valid!');
      iface.close();
      process.exit(1);
    }
    selectedWallets = wallets.slice(i);
  } else {
    console.error('Pilihan tidak valid!');
    iface.close();
    process.exit(1);
  }

  const twitterUsername = await ask(iface, '\nMasukkan username X (tanpa @): ');

  console.log(`\n🚀 Memproses ${selectedWallets.length} wallet...\n`);

  for (let i = 0; i < selectedWallets.length; i++) {
    const wallet = selectedWallets[i];
    console.log(`\n${'─'.repeat(50)}`);
    console.log(`Wallet ${i + 1}/${selectedWallets.length}: ${wallet.address}`);
    console.log('─'.repeat(50));

    try {
      await processWallet(wallet, twitterUsername.trim(), iface);
    } catch (err) {
      log(wallet, `❌ Error: ${err.message}`);
    }

    if (i < selectedWallets.length - 1) {
      log(wallet, 'Delay 3 detik sebelum akun berikutnya...');
      await sleep(3000);
    }
  }

  console.log('\n✅ Semua wallet selesai diproses!');
  iface.close();
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
