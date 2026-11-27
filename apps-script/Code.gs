/**
 * SEGO email verification (Google Apps Script web app).
 * Create this project while signed in as sego.institutional@gmail.com.
 * No password or API key goes in this file or on the website.
 */
var TTL_MS = 15 * 60 * 1000;      // code lifetime
var MAX_ATTEMPTS = 5;             // wrong tries before the code is voided
var RESEND_MS = 60 * 1000;        // one send per 60 seconds
var HOUR_MS = 60 * 60 * 1000;
var MAX_PER_HOUR = 5;             // per email address
var MAX_ALL_PER_HOUR = 30;        // whole site, limits abuse of the Gmail quota

/** Run once from the editor to grant permission to send mail. */
function authorize() {
  Logger.log('Emails remaining today: ' + MailApp.getRemainingDailyQuota());
}

function doPost(e) {
  var out;
  try {
    var req = JSON.parse(e.postData.contents);
    var email = String(req.email || '').trim().toLowerCase();
    if (email.length > 254 || !/^[^\s@,;<>]+@[^\s@,;<>]+\.[^\s@,;<>]+$/.test(email)) {
      out = { ok: false, code: 'bad_email' };
    } else {
      var lock = LockService.getScriptLock();
      lock.waitLock(20000);
      try {
        if (req.action === 'send') out = sendCode_(email);
        else if (req.action === 'verify') out = verifyCode_(email, String(req.pin || ''));
        else out = { ok: false, code: 'bad_request' };
      } finally {
        lock.releaseLock();
      }
    }
  } catch (err) {
    console.error('Request failed: ' + err.message);
    out = { ok: false, code: 'server_error' };
  }
  return ContentService.createTextOutput(JSON.stringify(out))
    .setMimeType(ContentService.MimeType.JSON);
}

function sendCode_(email) {
  var store = PropertiesService.getScriptProperties();
  var now = Date.now();
  var key = key_(email);
  var rec = JSON.parse(store.getProperty(key) || 'null') || { sends: [] };
  var sends = rec.sends.filter(function (t) { return now - t < HOUR_MS; });
  var last = sends.length ? sends[sends.length - 1] : 0;
  if (now - last < RESEND_MS) {
    return { ok: false, code: 'wait', seconds: Math.ceil((RESEND_MS - (now - last)) / 1000) };
  }
  if (sends.length >= MAX_PER_HOUR) return { ok: false, code: 'hourly_limit' };

  var all = JSON.parse(store.getProperty('all_sends') || '[]')
    .filter(function (t) { return now - t < HOUR_MS; });
  if (all.length >= MAX_ALL_PER_HOUR || MailApp.getRemainingDailyQuota() < 1) {
    return { ok: false, code: 'busy' };
  }

  var pin = newPin_();
  MailApp.sendEmail({
    to: email,
    subject: 'SEGO Capital Group: verification code',
    name: 'SEGO Capital Group',
    body: 'SEGO Capital Group\n\nVerification code: ' + pin +
      '\n\nThe code expires in 15 minutes and can be used once.' +
      '\n\nIf you did not request this, ignore this email.',
    htmlBody:
      '<div style="font-family:Georgia,serif;max-width:480px;margin:0 auto;padding:32px;color:#1a1f2b">' +
      '<div style="font-size:16px;letter-spacing:4px;font-weight:bold;border-bottom:2px solid #B8964F;padding-bottom:14px">SEGO CAPITAL GROUP</div>' +
      '<p style="margin-top:24px">Enter this code to verify the email address:</p>' +
      '<p style="font-size:38px;letter-spacing:10px;font-weight:bold;margin:20px 0">' + pin + '</p>' +
      '<p>The code expires in 15 minutes and can be used once.</p>' +
      '<p style="font-size:13px;color:#5a6272;border-top:1px solid #ddd;padding-top:14px">If you did not request this, ignore this email.</p></div>'
  });

  // Saved only after a successful send. Overwrites, so any earlier code stops working.
  sends.push(now);
  all.push(now);
  purge_(store, now);
  store.setProperty(key, JSON.stringify({
    h: hash_(email, pin), exp: now + TTL_MS, att: 0, sends: sends
  }));
  store.setProperty('all_sends', JSON.stringify(all));
  return { ok: true, code: 'sent' };
}

function verifyCode_(email, pin) {
  var store = PropertiesService.getScriptProperties();
  var key = key_(email);
  var rec = JSON.parse(store.getProperty(key) || 'null');
  if (!rec) return { ok: false, code: 'invalid' };
  if (rec.verified) return { ok: false, code: 'already_verified' };
  if (rec.att >= MAX_ATTEMPTS) return { ok: false, code: 'too_many' };
  if (Date.now() > rec.exp) return { ok: false, code: 'expired' };

  if (!/^\d{6}$/.test(pin) || hash_(email, pin) !== rec.h) {
    rec.att++;
    if (rec.att >= MAX_ATTEMPTS) rec.h = null;
    store.setProperty(key, JSON.stringify(rec));
    return rec.att >= MAX_ATTEMPTS
      ? { ok: false, code: 'too_many' }
      : { ok: false, code: 'invalid', left: MAX_ATTEMPTS - rec.att };
  }
  store.setProperty(key, JSON.stringify({ verified: true, at: Date.now(), sends: [] }));
  return { ok: true, code: 'verified' };
}

/** 6 digits derived from random UUIDs (Java secure random), without modulo bias. */
function newPin_() {
  while (true) {
    var b = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256,
      Utilities.getUuid() + Utilities.getUuid());
    var n = 0;
    for (var i = 0; i < 4; i++) n = n * 256 + (b[i] & 255);
    if (n < 4294000000) return ('00000' + (n % 1000000)).slice(-6);
  }
}

/** Keyed hash, so stored values cannot be reversed without the secret. */
function hash_(email, pin) {
  var store = PropertiesService.getScriptProperties();
  var secret = store.getProperty('secret');
  if (!secret) {
    secret = Utilities.getUuid() + Utilities.getUuid();
    store.setProperty('secret', secret);
  }
  return Utilities.base64Encode(Utilities.computeHmacSha256Signature(email + '|' + pin, secret));
}

function key_(email) {
  return 'u:' + Utilities.base64Encode(
    Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, email));
}

/** Removes unverified records more than a day old. */
function purge_(store, now) {
  var all = store.getProperties();
  Object.keys(all).forEach(function (k) {
    if (k.indexOf('u:') !== 0) return;
    var r = JSON.parse(all[k]);
    if (!r.verified && now - r.exp > 24 * HOUR_MS) store.deleteProperty(k);
  });
}
