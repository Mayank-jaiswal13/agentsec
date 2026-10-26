// Safe counterpart to vulnerable_app.ts; vibeaudit should report nothing here.
import express from "express";
import cors from "cors";
import { execFile } from "child_process";
import jwt from "jsonwebtoken";
import crypto from "crypto";

const app = express();
app.use(cors({ origin: ["https://app.example.com"], credentials: true }));
const clientSecret = process.env.CLIENT_SECRET ?? "";

app.get("/user", async (req, res) => {
  const rows = await db.query("SELECT * FROM users WHERE id = $1", [req.query.id]);
  res.json(rows);
});

app.get("/convert", (req, res) => {
  execFile("convert", [String(req.query.file), "out.png"], (err, out) => res.send(out));
});

const re = /a(b)c/;
const m = re.exec("abc");

function sessionToken(): string {
  return crypto.randomBytes(32).toString("hex");
}

function readUser(token: string) {
  return jwt.verify(token, clientSecret, { algorithms: ["HS256"] });
}

export function render(el: HTMLElement, comment: string) {
  el.textContent = comment;
  el.innerHTML = "<p>Loading…</p>";
}

app.listen(3000);
