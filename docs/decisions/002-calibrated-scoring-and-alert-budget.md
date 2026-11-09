# 002: Calibrated Scoring, Alert Budget & The Base-Rate Problem

**Status**: Accepted  
**Date**: 2026-11-10  

## Context
In dependency updates, real malicious releases are extremely rare (estimated prevalence $\pi \approx 0.1\%$ to $0.01\%$).
According to Bayes' theorem for positive predictive value (PPV):
$$\text{PPV} = \frac{\text{TPR} \cdot \pi}{\text{TPR} \cdot \pi + \text{FPR} \cdot (1 - \pi)}$$

If a detector has an FPR of 1% (99% specificity) and prevalence is 0.1%, PPV is under 10%—meaning 9 out of 10 alerts are false alarms. Developers quickly disable or ignore scanners that cry wolf.

## Decision
1. Calibrate decision thresholds from an **Alert Budget** (e.g., maximum 0.1% FPR) rather than raw accuracy.
2. Replace static heuristic priors with a regularized logistic regression model calibrated via **Platt scaling** on held-out clusters.
3. Quantify statistical uncertainty using **Wilson score 95% confidence intervals**.
4. Guarantee that near-duplicate malware samples never leak across train and test splits by partitioning strictly by **cluster group ID**.

## Consequences
- **Positive**: Probabilities behave like genuine confidence scores. Reason codes are derived from the largest feature contributions (`weight * value`).
- **Trade-off**: Requires empirical calibration benchmarks across both hijacked libraries and benign packages.

## Evidence
- `eval/results/results.json`: 100.0% PPV at 0.1% assumed prevalence with 0.0% false alarms.
