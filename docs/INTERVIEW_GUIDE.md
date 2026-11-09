# Interview Walkthrough & Rehearsal Guide

This guide provides concise, high-impact answers to technical interview questions about `bumpguard`. It is designed to demonstrate architectural maturity, sound risk management, and systems thinking.

---

### 1. "Can you give me a 30-second elevator pitch of Bumpguard?"
> "Bumpguard is a supply-chain risk scanner for pull requests. Unlike traditional scanners that inspect a package in isolation and generate huge false-alarm fatigue, Bumpguard diffs the new release against the previous release in-memory. By keying code facts by `(kind, api, context)` and subtracting old behavior from new behavior, we ignore baseline functionality and flag only genuinely new risk signals—like newly added network calls, publisher handovers, or hidden install hooks."

---

### 2. "Why compare releases instead of scanning the full package?"
> "Legitimate packages frequently use sensitive APIs—a CLI tool spawns child processes, and an HTTP library imports sockets. Scanning the whole package flags these every time. By focusing strictly on the delta (`new_facts - old_facts`), we eliminate noise. For example, if a library has used `child_process` for three years, doing so again in version 1.2.4 is not suspicious; but if a string-padding library suddenly introduces a network call on import, that's an immediate red flag."

---

### 3. "What is the Base-Rate Fallacy and how did you budget for noise?"
> "In dependency updates, real malware has an extremely low prevalence—around 0.1% or less. According to Bayes' theorem, if your false positive rate is even 1%, your Positive Predictive Value (PPV) drops below 10%, meaning over 90% of your alerts are false alarms. Developers quickly ignore tools that cry wolf. 
> To solve this, I designed Bumpguard around an **Alert Budget**—targeting at most 0.1% false-alarm rate on benign updates—and used Platt-scaled logistic regression to generate calibrated probabilities rather than arbitrary heuristic weights."

---

### 4. "How did you design the evaluation to prevent data leakage?"
> "Malware datasets often contain dozens of copycat or automated campaign variants. If you use random train/test splits, near-duplicate samples leak into the test set, creating artificially inflated recall numbers.
> I addressed this with two strict guardrails:
> 1. **Cluster-Aware Group Splits**: Samples sharing identical payload signatures or domains are clustered into group IDs, ensuring entire clusters reside strictly in either train or test.
> 2. **Separate Tracks**: I strictly separate the Diff Track (compromised libraries with available predecessors) from the New-Package Track (zero-history attack packages) so headline numbers are never mixed or overstated."

---

### 5. "How do you safely analyze untrusted archives?"
> "Safety is an absolute invariant. Bumpguard enforces zero code execution: we never invoke `npm install`, `node`, `pip`, or lifecycle scripts. Archives are parsed as in-memory byte streams with decompression bomb safeguards (capped file count, max 200MB expansion). Our `safe_path` sanitization rejects directory traversal attempts like `../../etc/passwd` before file contents are ever read."

---

### 6. "Why did you build the reference engine in Python, and how does it relate to Rust?"
> "In systems engineering, building a verified reference oracle in Python first is a recognized best practice. It allowed me to establish the mathematical baseline, evaluate the AST fact extraction logic, and fit the calibrated model with rapid iteration. The working Python engine now acts as our formal specification and regression test oracle for native porting, demonstrating practical delivery and risk management."
