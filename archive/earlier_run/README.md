# Earlier CodeBERT run (comparison only)

These files come from the first CodeBERT evaluation, a single-seed run that selected each fold's checkpoint on the
fold it was scored on and grouped folds by contract without merging duplicated code. Its figures (pooled MCC 0.406,
nine-class macro-F1 0.388) appear in the report only as the "earlier run" comparison column of Table 4.2, to show how
much those choices inflated the estimates (Section 4.2).

The results the report relies on are in [`../../codebert`](../../codebert).
