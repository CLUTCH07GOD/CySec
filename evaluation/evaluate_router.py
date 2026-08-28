"""
Router Evaluation — Confusion Matrix, Precision/Recall/F1
------------------------------------------------------------
Evaluates the domain-routing step of the NIST Multi-Domain Agent as a
multi-class classification problem:

    input:  a question text
    label:  which domain adapter it "should" route to (the domain folder
            it was sampled from)
    pred:   the domain the router (sentence-embedding centroid matching)
            actually picks for that question

To avoid data leakage, centroids are built from the first
`SAMPLES_PER_DOMAIN` questions in each domain's train.jsonl (same as the
main app), and evaluation is run on a separate held-out slice of
questions from the *same* files that were NOT used for the centroids.

Outputs:
    - confusion_matrix.png   (heatmap)
    - classification_report.txt  (per-domain precision/recall/F1 + accuracy)

Run with:
    python evaluate_router.py
"""

import os
import json
import glob

import numpy as np
import matplotlib.pyplot as plt
from sentence_transformers import SentenceTransformer
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay, classification_report

# ----------------------------------------------------------------------
# Config — keep in sync with app.py
# ----------------------------------------------------------------------
ADAPTERS_DIR = "adapters"
EMBED_MODEL_NAME = "all-MiniLM-L6-v2"
SAMPLES_PER_DOMAIN = 30     # used to build centroids (matches app.py)
EVAL_SAMPLES_PER_DOMAIN = 20  # held-out questions per domain for evaluation


def load_questions(domain_dir: str, start: int, count: int) -> list[str]:
    """Load `count` questions starting at line `start` from a domain's train.jsonl."""
    path = os.path.join(domain_dir, "train.jsonl")
    questions = []
    with open(path) as f:
        for i, line in enumerate(f):
            if i < start:
                continue
            if len(questions) >= count:
                break
            r = json.loads(line)
            questions.append(r["instruction"])
    return questions


def main():
    domain_dirs = sorted([d for d in glob.glob(f"{ADAPTERS_DIR}/*") if os.path.isdir(d)])
    domains = [os.path.basename(d) for d in domain_dirs]

    if not domains:
        raise FileNotFoundError(f"No domain subfolders found under ADAPTERS_DIR='{ADAPTERS_DIR}'.")

    print(f"Found domains: {domains}")
    embedder = SentenceTransformer(EMBED_MODEL_NAME)

    # ---- Build centroids from the SAME questions the app uses (rows 0..SAMPLES_PER_DOMAIN) ----
    centroids = {}
    for domain, path in zip(domains, domain_dirs):
        train_qs = load_questions(path, start=0, count=SAMPLES_PER_DOMAIN)
        embeddings = embedder.encode(train_qs)
        centroids[domain] = np.mean(embeddings, axis=0)
        print(f"{domain}: centroid built from {len(train_qs)} training questions")

    # ---- Build held-out eval set from the NEXT slice of questions (no overlap) ----
    y_true = []
    y_pred = []
    for domain, path in zip(domains, domain_dirs):
        eval_qs = load_questions(path, start=SAMPLES_PER_DOMAIN, count=EVAL_SAMPLES_PER_DOMAIN)
        if not eval_qs:
            print(f"WARNING: no held-out questions left for '{domain}' "
                  f"(train.jsonl may have fewer than {SAMPLES_PER_DOMAIN + EVAL_SAMPLES_PER_DOMAIN} lines)")
            continue

        q_embs = embedder.encode(eval_qs)
        for q_emb in q_embs:
            sims = {
                d: float(np.dot(q_emb, c) / (np.linalg.norm(q_emb) * np.linalg.norm(c)))
                for d, c in centroids.items()
            }
            predicted_domain = max(sims, key=sims.get)
            y_true.append(domain)
            y_pred.append(predicted_domain)

        print(f"{domain}: evaluated on {len(eval_qs)} held-out questions")

    if not y_true:
        raise RuntimeError("No evaluation samples collected — check train.jsonl sizes per domain.")

    # ---- Confusion matrix ----
    cm = confusion_matrix(y_true, y_pred, labels=domains)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=domains)
    fig, ax = plt.subplots(figsize=(7, 6))
    disp.plot(cmap=plt.cm.Blues, ax=ax, xticks_rotation=45)
    plt.title("Router Confusion Matrix (Domain Classification)", fontsize=13, pad=15)
    plt.tight_layout()
    plt.savefig("confusion_matrix.png", dpi=150)
    print("\nSaved confusion_matrix.png")

    # ---- Classification report (precision, recall, F1, accuracy) ----
    report = classification_report(y_true, y_pred, labels=domains, target_names=domains, zero_division=0)
    print("\n" + report)

    with open("classification_report.txt", "w") as f:
        f.write(f"Router evaluation — {len(y_true)} held-out samples across {len(domains)} domains\n")
        f.write("=" * 70 + "\n\n")
        f.write(report)
    print("Saved classification_report.txt")


if __name__ == "__main__":
    main()
