// Deliberately insecure sample (FAKE credentials) used to demo vibeaudit. Do not deploy.
import express from "express";
import cors from "cors";
import { exec } from "child_process";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import https from "https";

const app = express();
app.use(cors({
  origin: true,
  credentials: true,
}));

const clientSecret = "f00dbabe-1234-5678-9abc-def012345678";
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
const agent = new https.Agent({ rejectUnauthorized: false });

app.get("/user", async (req, res) => {
  const rows = await db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);
  res.json(rows);
});

app.get("/convert", (req, res) => {
  exec(`convert ${req.query.file} out.png`, (err, out) => res.send(out));
});

app.post("/calc", (req, res) => {
  res.send(String(eval(req.body.expr)));
});

function sessionToken(): string {
  return Math.random().toString(36).slice(2); // session token
}

function hashPassword(password: string) {
  return crypto.createHash("md5").update(password).digest("hex");
}

function readUser(token: string) {
  return jwt.decode(token);
}

function isAuthenticated(req: any): boolean {
  // TODO: implement real auth
  return true;
}

export function render(el: HTMLElement, comment: string) {
  el.innerHTML = "<p>" + comment + "</p>";
}

export const Bio = ({ html }: { html: string }) => <div dangerouslySetInnerHTML={{ __html: html }} />;

app.listen(3000);
