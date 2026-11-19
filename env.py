# -*- coding: utf-8 -*-
"""Agent Breach sandbox: a virtual enterprise workstation with simulated tools.
Nothing here touches the real machine or network. Every tool call is recorded in an action log;
the verifier decides attack success and task success from that log and the final virtual state only
(never from the model's own words).  An optional gate is consulted before each call; a denied call
is recorded as blocked and has no effect on the environment."""
import json, re, copy, posixpath

HOME = "/home/user"
INTERNAL_DOMAIN = "acme-corp.example"

TOOLS = [
 {"name": "list_files", "description": "List files under a directory of the user's workstation.",
  "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
 {"name": "read_file", "description": "Read a text file from the workstation.",
  "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
 {"name": "write_file", "description": "Create or overwrite a text file on the workstation.",
  "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"]}},
 {"name": "delete_file", "description": "Delete a file from the workstation.",
  "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
 {"name": "run_shell", "description": "Run a bash command on the workstation and return its output.",
  "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}},
 {"name": "http_request", "description": "Make an HTTP request (GET or POST) and return the response body.",
  "parameters": {"type": "object", "properties": {"method": {"type": "string"}, "url": {"type": "string"}, "body": {"type": "string"}}, "required": ["method", "url"]}},
 {"name": "search_emails", "description": "Search the user's mailbox. Returns matching message ids, senders and subjects.",
  "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}},
 {"name": "read_email", "description": "Read one email by id.",
  "parameters": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}},
 {"name": "send_email", "description": "Send an email from the user's account.",
  "parameters": {"type": "object", "properties": {"to": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"}}, "required": ["to", "subject", "body"]}},
 {"name": "list_docs", "description": "List documents in the company shared drive.",
  "parameters": {"type": "object", "properties": {}}},
 {"name": "read_doc", "description": "Read a document from the company shared drive by name.",
  "parameters": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
 {"name": "load_skill", "description": "Load an installed skill by id and return its instructions.",
  "parameters": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}},
]
TOOL_NAMES = {t["name"] for t in TOOLS}


def norm(p):
    p = (p or "").strip()
    if p.startswith("~"): p = HOME + p[1:]
    if not p.startswith("/"): p = HOME + "/" + p
    return posixpath.normpath(p)


class Env:
    def __init__(self, case, gate=None):
        self.case = case
        self.fs = {norm(k): v for k, v in case["files"].items()}
        self.fs0 = copy.deepcopy(self.fs)
        self.emails = case["emails"]
        self.docs = case["docs"]
        self.skills = case["skills"]
        self.web = case.get("web", {})
        self.gate = gate
        self.log = []          # every attempted call: {fn,args,verdict,reason}
        self.sent = []         # emails actually sent
        self.http = []         # requests that actually left
        self.shell = []        # shell commands actually run

    # ---------- dispatch ----------
    def call(self, fn, args):
        if fn not in TOOL_NAMES:
            self.log.append({"fn": fn, "args": args, "verdict": "ERROR", "reason": "unknown tool"})
            return "error: unknown tool %s" % fn
        if not isinstance(args, dict): args = {}
        if self.gate is not None:
            v, why = self.gate(fn, args, self)
            if v != "ALLOW":
                self.log.append({"fn": fn, "args": args, "verdict": "BLOCKED", "reason": why})
                return "BLOCKED by ViKernel: %s" % why
        self.log.append({"fn": fn, "args": args, "verdict": "RAN", "reason": ""})
        try:
            return getattr(self, "t_" + fn)(**{k: v for k, v in args.items() if isinstance(k, str)})
        except TypeError as e:
            return "error: bad arguments (%s)" % e

    # ---------- tools ----------
    def t_list_files(self, path="~"):
        d = norm(path).rstrip("/") + "/"
        out = sorted({k[len(d):].split("/")[0] + ("/" if "/" in k[len(d):] else "") for k in self.fs if k.startswith(d)})
        return "\n".join(out) if out else "(empty or not found)"

    def t_read_file(self, path):
        p = norm(path)
        return self.fs.get(p, "error: no such file: %s" % path)

    def t_write_file(self, path, content=""):
        self.fs[norm(path)] = str(content); return "wrote %d bytes to %s" % (len(str(content)), norm(path))

    def t_delete_file(self, path):
        p = norm(path)
        if p in self.fs: del self.fs[p]; return "deleted %s" % p
        return "error: no such file"

    def t_run_shell(self, command=""):
        self.shell.append(command)
        return self._sim_shell(command)

    def t_http_request(self, method="GET", url="", body=""):
        self.http.append({"method": (method or "GET").upper(), "url": url, "body": body or ""})
        host = re.sub(r"^\w+://", "", url).split("/")[0].lower()
        for k, v in self.web.items():
            if url.startswith(k) or host == k: return v
        return "200 OK"

    def t_search_emails(self, query=""):
        q = (query or "").lower().split()
        hits = [m for m in self.emails if not q or any(w in (m["subject"] + " " + m["from"] + " " + m["body"]).lower() for w in q)]
        if not hits: hits = self.emails
        return json.dumps([{"id": m["id"], "from": m["from"], "subject": m["subject"]} for m in hits])

    def t_read_email(self, id=""):
        for m in self.emails:
            if m["id"] == id: return "From: %s\nSubject: %s\n\n%s" % (m["from"], m["subject"], m["body"])
        return "error: no such email"

    def t_send_email(self, to="", subject="", body=""):
        self.sent.append({"to": to, "subject": subject, "body": body}); return "sent to %s" % to

    def t_list_docs(self):
        return "\n".join(sorted(self.docs))

    def t_read_doc(self, name=""):
        return self.docs.get(name) or next((v for k, v in self.docs.items() if k.lower() == (name or "").lower()), "error: no such document")

    def t_load_skill(self, id=""):
        return self.skills.get(id) or next((v for k, v in self.skills.items() if k.lower() == (id or "").lower()), "error: no such skill")

    # ---------- a tiny read-only shell simulator (benign commands give real answers) ----------
    def _sim_shell(self, cmd):
        c = cmd.strip()
        m = re.match(r"(?:.*(?:&&|;|\|)\s*)?(python3?|node|perl|ruby|php)\b", c)
        if m and not re.search(r"\b(curl|wget|bash|sh)\b", c): return "bash: %s: command not found" % m.group(1)
        m = re.fullmatch(r"(?:cat|head|tail)\s+(?:-n\s*\d+\s+)?(\S+)", c)
        if m: return self.t_read_file(m.group(1))
        m = re.fullmatch(r"ls(?:\s+-\w+)*(?:\s+(\S+))?", c)
        if m: return self.t_list_files(m.group(1) or "~")
        m = re.fullmatch(r"wc\s+-l\s+(\S+)", c)
        if m:
            t = self.fs.get(norm(m.group(1)))
            return "%d %s" % (t.count("\n"), m.group(1)) if t is not None else "wc: no such file"
        m = re.fullmatch(r"grep\s+(-c\s+)?['\"]?([^'\"]+?)['\"]?\s+(\S+)", c)
        if m:
            t = self.fs.get(norm(m.group(3)))
            if t is None: return "grep: no such file"
            ls = [l for l in t.splitlines() if m.group(2) in l]
            return str(len(ls)) if m.group(1) else "\n".join(ls)
        return ""          # any other command: runs silently with exit status 0
