const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const path = require("path");
const querystring = require("querystring");

const PORT = 8080;
const ROOT = __dirname;
const DATABASE = path.join(ROOT, "data", "accounts.db");
const HASH_ITERATIONS = 210_000;
const HASH_LENGTH = 32;

function ensureDatabase() {
  fs.mkdirSync(path.dirname(DATABASE), { recursive: true });
  if (!fs.existsSync(DATABASE)) fs.writeFileSync(DATABASE, "# username|birthDate|salt|passwordHash\n");
}

function getAge(birthDate) {
  const today = new Date();
  const date = new Date(`${birthDate}T00:00:00`);
  let age = today.getFullYear() - date.getFullYear();
  if (today.getMonth() < date.getMonth() || (today.getMonth() === date.getMonth() && today.getDate() < date.getDate())) age -= 1;
  return age;
}

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, HASH_ITERATIONS, HASH_LENGTH, "sha256");
}

function readAccounts() {
  return fs.readFileSync(DATABASE, "utf8").split(/\r?\n/).filter((line) => line && !line.startsWith("#"))
    .map((line) => { const [username, birthDate, salt, passwordHash] = line.split("|"); return { username, birthDate, salt, passwordHash }; });
}

function sendJson(response, status, message) {
  response.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  response.end(JSON.stringify({ message }));
}

function register(form, response) {
  const { username = "", birthDate = "", password = "" } = form;
  if (!/^[A-Za-z0-9_-]{3,24}$/.test(username)) return sendJson(response, 400, "Use 3 to 24 letters, numbers, _ or - in your username.");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(birthDate) || getAge(birthDate) < 18) return sendJson(response, 400, "You must be at least 18 years old to create an account.");
  if (password.length < 8) return sendJson(response, 400, "Your password must contain at least 8 characters.");
  if (readAccounts().some((account) => account.username.toLowerCase() === username.toLowerCase())) return sendJson(response, 400, "This username already exists.");

  const salt = crypto.randomBytes(16);
  const hash = hashPassword(password, salt);
  fs.appendFileSync(DATABASE, `${username}|${birthDate}|${salt.toString("base64")}|${hash.toString("base64")}\n`);
  return sendJson(response, 201, "Account created. You can now sign in.");
}

function login(form, response) {
  const account = readAccounts().find((item) => item.username.toLowerCase() === (form.username || "").toLowerCase());
  if (!account) return sendJson(response, 401, "Incorrect username or password.");
  const expectedHash = Buffer.from(account.passwordHash, "base64");
  const actualHash = hashPassword(form.password || "", Buffer.from(account.salt, "base64"));
  if (!crypto.timingSafeEqual(expectedHash, actualHash)) return sendJson(response, 401, "Incorrect username or password.");
  return sendJson(response, 200, "You are signed in.");
}

function serveStaticFile(request, response) {
  const requestedPath = request.url === "/" ? "index.html" : decodeURIComponent(request.url.split("?")[0]).replace(/^\//, "");
  const filePath = path.resolve(ROOT, requestedPath);
  if (!filePath.startsWith(ROOT) || !fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) { response.writeHead(404); return response.end(); }
  const types = { ".css": "text/css", ".js": "application/javascript", ".html": "text/html" };
  response.writeHead(200, { "Content-Type": `${types[path.extname(filePath)] || "application/octet-stream"}; charset=utf-8` });
  response.end(fs.readFileSync(filePath));
}

ensureDatabase();
http.createServer((request, response) => {
  if (request.method === "POST" && ["/api/register", "/api/login"].includes(request.url)) {
    let body = "";
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => request.url === "/api/register" ? register(querystring.parse(body), response) : login(querystring.parse(body), response));
    return;
  }
  serveStaticFile(request, response);
}).listen(PORT, () => console.log(`Token Arcade draait op http://localhost:${PORT}`));
