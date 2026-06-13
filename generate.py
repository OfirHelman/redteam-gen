import os
import json
import csv
import time
import random
import math
from concurrent.futures import ThreadPoolExecutor

from dotenv import load_dotenv
from openai import AzureOpenAI

load_dotenv()

ENDPOINT = os.environ["AZURE_OPENAI_ENDPOINT"]
API_KEY = os.environ["AZURE_OPENAI_API_KEY"]
DEPLOYMENT = os.environ["AZURE_OPENAI_DEPLOYMENT"]
API_VERSION = os.environ["AZURE_OPENAI_API_VERSION"]

client = AzureOpenAI(
    azure_endpoint=ENDPOINT,
    api_key=API_KEY,
    api_version=API_VERSION,
)


def build_prompt(scenario, n_malicious, n_benign):
    return f"""Generate synthetic, labeled command-line telemetry for a detection
exercise based on the theme "{scenario}".

Return ONLY valid JSON (no markdown, no commentary) shaped exactly like this:
{{
  "story": "...",
  "commands": [
    {{"process_name": "...", "command_line": "...", "label": "malicious" | "benign"}}
  ]
}}

Requirements:
- "story": a short narrative describing how the "{scenario}" sequence unfolds.
- Exactly {n_malicious} entries labeled "malicious" that follow a logical "{scenario}"
  sequence from start to finish.
- Exactly {n_benign} entries labeled "benign" representing ordinary activity as noise.
- Use realistic process names and command-line syntax.
- Mix the labeled entries together; do not group them by label.
- Total entries: exactly {n_malicious + n_benign}.
"""


def build_benign_prompt(n_benign):
    return f"""Generate a synthetic dataset of {n_benign} realistic command-line entries
representing normal everyday computer activity (developers, sysadmins, regular users).

Return ONLY valid JSON (no markdown, no commentary) shaped exactly like this:
{{
  "commands": [
    {{"process_name": "...", "command_line": "...", "label": "benign"}}
  ]
}}

Requirements:
- Exactly {n_benign} entries, all labeled "benign".
- Use real process names and realistic syntax (e.g. git, python, npm, bash, powershell.exe).
- Vary the activity: code builds, file edits, package installs, queries, routine admin tasks.
"""


def build_twin_prompt(tools, n):
    tool_list = ", ".join(sorted(tools))
    return f"""Generate {n} realistic benign command-line entries representing LEGITIMATE
everyday system administration, using these specific tools: {tool_list}.

These are normal IT/admin tasks (inventory, service checks, file copies, remote
management, scripting) that happen to rely on the same utilities power users use daily.

Return ONLY valid JSON (no markdown, no commentary) shaped exactly like this:
{{
  "commands": [
    {{"process_name": "...", "command_line": "...", "label": "benign"}}
  ]
}}

Requirements:
- Exactly {n} entries, all labeled "benign".
- Each entry must use one of these processes: {tool_list}.
- Realistic syntax, ordinary administrative intent (no attacks).
"""


def call_model(prompt, max_attempts=6):
    """Send one prompt; retry if the filter blocks it; return parsed JSON."""
    for attempt in range(max_attempts):
        try:
            response = client.chat.completions.create(
                model=DEPLOYMENT,
                messages=[{"role": "user", "content": prompt}],
            )
            return json.loads(response.choices[0].message.content)
        except Exception:
            print(f"  attempt {attempt + 1} blocked, retrying...")
            time.sleep(1)
    raise SystemExit("Filter blocked all attempts for this batch.")


def dedupe(items, n):
    """Keep unique command_lines first; only reuse duplicates if needed to reach n."""
    seen, unique, extra = set(), [], []
    for it in items:
        key = it["command_line"]
        if key not in seen:
            seen.add(key)
            unique.append(it)
        else:
            extra.append(it)
    result = unique[:n]
    i = 0
    while len(result) < n and i < len(extra):
        result.append(extra[i])
        i += 1
    return result[:n]


def scatter_constraint_met(rows):
    """Check that no more than 2 consecutive malicious commands."""
    consecutive = 0
    for row in rows:
        if row["label"] == "malicious":
            consecutive += 1
            if consecutive > 2:
                return False
        else:
            consecutive = 0
    return True


def enforce_scatter(rows, max_tries=100):
    """Reshuffle until scatter constraint is met (max 2 malicious in a row)."""
    for attempt in range(max_tries):
        shuffled = rows.copy()
        random.shuffle(shuffled)
        if scatter_constraint_met(shuffled):
            return shuffled
    print(f"Warning: scatter constraint not met after {max_tries} tries; returning best effort")
    return shuffled


def generate_dataset(scenario, n_malicious=20, n_benign=200, batch=5, benign_chunks=2):
    per_chunk = n_benign // benign_chunks + 10
    n_mal_batches = math.ceil(n_malicious / batch) + 2

    tasks = [("benign", build_benign_prompt(per_chunk)) for _ in range(benign_chunks)]
    tasks += [("malicious", build_prompt(scenario, batch, 0)) for _ in range(n_mal_batches)]

    print(f"Sending {len(tasks)} requests in parallel...")
    with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
        results = list(pool.map(lambda t: (t[0], call_model(t[1])), tasks))

    benign, malicious, story = [], [], ""
    for kind, data in results:
        cmds = data["commands"]
        if kind == "benign":
            benign += [c for c in cmds if c["label"] == "benign"]
        else:
            malicious += [c for c in cmds if c["label"] == "malicious"]
            if not story:
                story = data.get("story", "")

    malicious = dedupe(malicious, n_malicious)

    # Twins: benign lookalikes using the SAME tools the attack used
    tools = {m["process_name"] for m in malicious}
    twins = []
    if tools:
        print("Generating benign twins...")
        twin_data = call_model(build_twin_prompt(tools, 40))
        twins = [c for c in twin_data["commands"] if c["label"] == "benign"]

    # Prioritize twins (prepend them so dedupe keeps them first)
    benign = dedupe(twins + benign, n_benign)
    rows = benign + malicious

    # Enforce scatter: no more than 2 consecutive malicious
    print("Enforcing scatter constraint...")
    rows = enforce_scatter(rows)

    return rows, story


if __name__ == "__main__":
    rows, story = generate_dataset("ransomware", 20, 200, batch=5)

    with open("dataset.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["process_name", "command_line", "label"])
        writer.writeheader()
        writer.writerows(rows)

    with open("ground_truth.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["process_name", "command_line", "label"])
        writer.writeheader()
        writer.writerows([r for r in rows if r["label"] == "malicious"])

    total = len(rows)
    mal = sum(1 for r in rows if r["label"] == "malicious")
    print(f"\nWrote {total} rows: {mal} malicious, {total - mal} benign")
    print(f"Story: {story}")