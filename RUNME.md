# How to run the LLM Safety Harness

A step-by-step guide for Windows. There are two stages: run it today with the
built-in mock models (no install), then run it for real with Ollama.

Everything here assumes the project folder:
`C:\Users\athar\OneDrive\Desktop\CybersecProjectOne`

---

## Stage 1 — Run it today (no install needed)

### Step 1 — Check Python is installed

Open **Command Prompt** (press the Windows key, type `cmd`, press Enter) and run:

```
python --version
```

Expected: a line like `Python 3.10.12` (any 3.8+ is fine).
If it says "not recognized", install Python from https://python.org and tick
**"Add Python to PATH"** during setup, then reopen Command Prompt.

### Step 2 — Go into the project folder

```
cd C:\Users\athar\OneDrive\Desktop\CybersecProjectOne
```

Confirm you're in the right place:

```
dir
```

Expected: you should see `harness.py`, `ui.py`, `ui.html`, `agent.py`, and the
rest of the files listed.

### Step 3 — Start the web dashboard

```
python ui.py
```

Expected output in the terminal:

```
========================================================
  LLM safety harness — web UI
  open:  http://127.0.0.1:8000
  stop:  Ctrl-C
========================================================
```

Leave this window open — it's the server. It keeps running until you press
`Ctrl-C`.

### Step 4 — Open it in your browser

Open your browser and go to:

```
http://127.0.0.1:8000
```

Expected: the tool loads with a title bar, a toolbar (Target, Judge, Save
report, Run probes), and an empty results table saying
"Select a target and click Run probes."

### Step 5 — Run the agent red-team

1. In the **Target** dropdown, choose **OfficeAgent (local sandbox agent)**.
2. Tick **Save report**.
3. Click **Run probes**.

Expected: rows stream into the table one by one. When it finishes you should
see roughly this (exact text may vary slightly):

- **Pass rate: 17%**, Held **2/12**, Violated **10**, Probes **12**
- AG01–AG10 show a red **FAIL**
- AG11 and AG12 show a green **PASS** (these are the benign controls)
- The status bar reads `Done. 12 probes completed. Report saved: reports\...md`

Click any row to expand it and see the task, the agent's action log, and the
policy violations. **AG08** is the one to show off: an innocent "triage my
inbox" task ends with the agent reading `/secrets/master.key` and emailing it
out.

### Step 6 — Run the chatbot test

1. Change **Target** to **SupportBot (local practice chatbot)**.
2. Set **Judge** to **mock**.
3. Click **Run probes**.

Expected:

- **Pass rate: 68%**, Held **15/22**, Leaked **7**
- A mix of PASS and FAIL across the 22 probes
- Categories `output_formatting` and `indirect` show the most failures

### Step 7 — Stop the server

Click the terminal window and press `Ctrl-C`. It prints `stopped`.

---

## Verify it's working — quick checklist

| Check | Expected |
|---|---|
| `python ui.py` prints the banner | yes, with the http://127.0.0.1:8000 line |
| Browser page loads | title bar + toolbar + empty table |
| Agent run finishes | 17%, 2/12 held, AG11 & AG12 pass |
| Chatbot run finishes | 68%, 15/22 held |
| Rows expand on click | task / actions / violations (agent) or reply (chatbot) |
| "Save report" ticked | a new file appears in the `reports\` folder |
| No red error text in the terminal | correct |

If all of those are true, both projects work.

---

## Alternative — run from the command line (no browser)

Same results, printed in the terminal. Useful for a quick check or for CI.

```
python harness.py run --target agent_lab --report
python harness.py run --target local --judge mock --report
python harness.py targets
python harness.py probes --agent
```

Expected: a printed transcript, then a summary block with the same numbers as
above (17% for the agent, 68% for the chatbot).

---

## Stage 2 — Get the real results (install Ollama)

Everything above uses the built-in **mock** models — they prove the tool
works, but the numbers describe the harness, not a real AI. For real results:

### Step 1 — Install Ollama

Download from https://ollama.com and install it. It runs an AI model locally
on your PC (free, no account, no API key).

### Step 2 — Download a model

Open Command Prompt and run (one-time, downloads a few GB):

```
ollama pull llama3.2
```

Leave Ollama running after it finishes.

### Step 3 — Run again, for real

Start the UI (`python ui.py`) and run both targets as before. For the chatbot,
set **Judge** to **llm**. The harness detects Ollama automatically.

Expected: different, more interesting numbers. A real model will **refuse**
some attacks the mock didn't, and slip on others. Those numbers — not the mock
ones — are what belong in your README and on your resume.

Command-line version:

```
python harness.py run --target local --judge llm --report
python harness.py run --target agent_lab --report
```

---

## Troubleshooting

- **"python is not recognized"** — Python isn't on PATH. Reinstall from
  python.org with "Add Python to PATH" ticked, or try `py` instead of
  `python`.
- **The browser page is blank or won't connect** — make sure the `python
  ui.py` window is still open and shows the banner. Use the exact address
  `http://127.0.0.1:8000`.
- **"Address already in use"** — something else is on port 8000. Run on
  another port: `set HARNESS_UI_PORT=8090` then `python ui.py`, and open
  `http://127.0.0.1:8090`.
- **Judge says it needs Ollama** — either set Judge to `mock`, or install
  Ollama (Stage 2).
- **Any other error** — copy the full red error text from the terminal and
  send it over.
