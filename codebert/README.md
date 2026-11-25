# CodeBERT component (report Chapter 3.7 and Chapter 4 Part A)

| Path | Contents |
|---|---|
| `CodeBERT_SmartBugs_Rerun_v3.ipynb` | The notebook that produced the reported results (Kaggle, Tesla T4, seeds 42, 43, 44) |
| `data/functions.csv` | 993 function bodies from the 143 SmartBugs Curated contracts (commit `230e649`), with function-level labels; functions without an annotated line are labelled benign |
| `results/duplicate_screening.json`, `results/duplicate_functions.csv` | Exact-duplicate screening: 89 duplicated bodies, 259 functions, 66 contracts, 92 CV groups (Section 3.4) |
| `results/oof_probs_*_seed{42,43,44}.csv` | Out-of-fold class probabilities for every function, with fold and contract id |
| `results/metrics_focal_weighted.csv` | Pooled and per-fold metrics for every seed and decision rule (Tables 4.1, 4.2, C.1, C.2) |
| `results/table_pooled_*.csv`, `results/table_folds_*.csv` | Mean and SD summaries of the above |
| `results/per_class_focal_weighted.csv` | Per-class precision, recall, F1, ROC-AUC, AP and one-vs-rest threshold F1 (Tables 4.3, 4.4, D.1) |
| `results/confusion_*_seed42.csv`, `results/fig_confusion_*.png` | Confusion matrices, default decision and nested thresholds (Figure 4.3, Section 4.8) |
| `results/ece_focal_weighted.json` | Expected calibration error per seed (Section 4.7) |
| `results/best_epochs_focal_weighted.json` | Early-stopping epochs selected on the inner split |
| `results/fig_training_curves_focal_weighted.png` | Figure 4.1 |
| `results/environment.json` | Exact software versions of the run (Table E.1) |
| `results/codebert_findings_poc.json` | Empty: the proof-of-concept `.sol` files were not attached in this run, so no CodeBERT findings on them exist yet (future work, Section 5.7) |
| `figures/` | Figures 4.2 and 4.4 to 4.7, drawn from the out-of-fold files above |
