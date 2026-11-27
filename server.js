// 가입/로그인/리더보드용 작은 서버 (추가 설치 없이 Node.js 기본 기능만 사용)
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const FILE = path.join(__dirname, 'data.json');
let db = { users: {}, tokens: {} };
try { db = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch (e) {}
const save = () => { try { fs.writeFileSync(FILE, JSON.stringify(db)); } catch (e) {} };
const hash = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');
const send = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
const newToken = key => { const t = crypto.randomBytes(24).toString('hex'); db.tokens[t] = key; save(); return t; };

http.createServer((req, res) => {
  const url = req.url.split('?')[0];
  if (req.method === 'GET' && !url.startsWith('/api/')) {
    fs.readFile(path.join(__dirname, 'index.html'), (e, d) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(d);
    });
    return;
  }
  let body = '';
  req.on('data', c => { body += c; if (body.length > 10000) req.destroy(); });
  req.on('end', () => {
    let b = {}; try { b = JSON.parse(body || '{}'); } catch (e) {}
    const key = db.tokens[(req.headers.authorization || '').replace('Bearer ', '')];
    const me = key && db.users[key];
    const nick = String(b.nick || '').trim(), pw = String(b.pw || '');

    if (url === '/api/signup' && req.method === 'POST') {
      if (nick.length < 2 || nick.length > 12) return send(res, 400, { error: '닉네임은 2~12글자로 정해주세요' });
      if (pw.length < 4) return send(res, 400, { error: '비밀번호는 4글자 이상이어야 해요' });
      const k = nick.toLowerCase();
      if (db.users[k]) return send(res, 409, { error: '이미 있는 닉네임이에요' });
      const salt = crypto.randomBytes(8).toString('hex');
      db.users[k] = { nick, salt, hash: hash(pw, salt), best: 0 };
      return send(res, 200, { token: newToken(k), nick, best: 0 });
    }
    if (url === '/api/login' && req.method === 'POST') {
      const u = db.users[nick.toLowerCase()];
      if (!u || !crypto.timingSafeEqual(Buffer.from(hash(pw, u.salt)), Buffer.from(u.hash)))
        return send(res, 401, { error: '닉네임이나 비밀번호가 틀렸어요' });
      return send(res, 200, { token: newToken(nick.toLowerCase()), nick: u.nick, best: u.best });
    }
    if (url === '/api/me') return me ? send(res, 200, { nick: me.nick, best: me.best }) : send(res, 401, { error: '로그인이 필요해요' });
    if (url === '/api/score' && req.method === 'POST') {
      if (!me) return send(res, 401, { error: '로그인이 필요해요' });
      const cpm = Math.round(Number(b.cpm));
      if (cpm > 0 && cpm < 1500 && cpm > me.best) { me.best = cpm; save(); }
      return send(res, 200, { best: me.best });
    }
    if (url === '/api/board') {
      const top = Object.values(db.users).filter(u => u.best > 0).sort((a, c) => c.best - a.best).slice(0, 10)
        .map(u => ({ nick: u.nick, best: u.best }));
      return send(res, 200, top);
    }
    send(res, 404, { error: '없는 주소예요' });
  });
}).listen(process.env.PORT || 3000);
