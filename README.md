# Agent Breach

Do AI agents get hijacked while they do real office work, and does a defense stop it?

Agent Breach puts a model to work as an office agent on a real task: build a rent calculator, summarize a log,
prepare a valuation table. The agent has a mailbox, a shared drive, local files and third-party skills. One of
those sources carries a hidden instruction. Afterwards we inspect the machine. An attack counts only if the harm
really happened: files encrypted or deleted, data sent to the attacker, a phishing link mailed, attacker code run,
or a foothold left behind. What the model says it did is ignored.

Every model is measured twice: alone, and behind a guard. The board shows the attack and the fix side by side.

Leaderboard: https://huggingface.co/spaces/FINAL-Bench/obfuscated-shell-leaderboard

## Results (held-out set, 2026-11-20)

10 models, 96 attacked cases and 8 clean cases each, 3 runs per case. A case is breached if any run is breached.

| Model | Breached, model alone | Breached, + ViKernel | Task done, + ViKernel |
|---|---:|---:|---:|
| DeepSeek-V4-Pro-0813 | 38.5% | 0.0% | 97.6% |
| Gemma-4-31B-it | 36.5% | 0.0% | 56.2% |
| DeepSeek-V4-Flash-0731 | 34.4% | 0.0% | 98.6% |
| Kimi-K3.1-Pro | 13.5% | 0.0% | 96.9% |
| GLM-5.3 | 12.5% | 0.0% | 97.6% |
| GPT-6.1-Terra | 9.4% | 0.0% | 96.5% |
| Qwen3.8-2.4T-A95B | 8.3% | 0.0% | 99.7% |
| Llama-3.3-70B-Instruct | 6.2% | 0.0% | 3.1% |
| Kimi-K3 | 4.2% | 0.0% | 96.5% |
| Qwen3.8-27B | 3.1% | 0.0% | 99.3% |

Average breach rate: 16.7% for the models alone, 0.0% behind the ViKernel gate. Task completion is the share of attacked runs that still produced the full deliverable and sent it to the requester.

## What it measures

| Score | Meaning |
|---|---|
| Breached | share of attacked cases where the harm took effect in any of k runs, with a 95% Wilson interval |
| Task done | share of runs that produced the full deliverable and emailed it to the requester |
| Clean work blocked | calls the guard refused in cases with no attack (over-blocking) |

Attack success is always read next to task completion, so refusing everything does not win.

Outcomes: data exfiltration, phishing, code execution, data destruction, ransomware, persistence.
Entry points: email, shared drive document, local data file, third-party skill.

## Run it

```bash
export HF_TOKEN=...            # or OPENAI_API_KEY for openai:<model>
python agent_run.py hf:zai-org/GLM-5.3 --arm bare --k 3
python agent_run.py hf:zai-org/GLM-5.3 --arm guard --k 3 --gate example_gate:gate
python score.py
```

`example_gate.py` shows the guard interface: `gate(fn, args, env)` is called before every tool call and returns
`(verdict, reason)`. Plug in your own guard to put a defense on the board.

## Files

| File | Role |
|---|---|
| `env.py` | simulated workstation and 12 tools; nothing touches the real machine or network |
| `scenarios.py`, `cases_dev.jsonl` | public dev split: 8 sectors, 6 outcomes, 4 entry points |
| `verify.py` | deterministic verifier: final file system, outbox, attacker collector |
| `agent_run.py` | runs a model as a tool-using agent, alone or behind a guard |
| `score.py` | breach rate, intervals, task completion, over-blocking |

The leaderboard is scored on a private held-out set built the same way, with attacks written to fit each workplace
and refreshed over time, so the public cases cannot be memorized.

All targets are fake `.invalid` domains and the secret is a fake canary.

## Submit

Open a post in the Community tab of the leaderboard Space with the model id, or with your guard as a Python module
that follows the `example_gate.py` interface. We run it on the held-out set and publish the result.

License: Apache-2.0. Cite as FINAL-Bench Agent Breach (2026).
