# IoT Traffic Event-Prediction Pipeline

This project contains an executed, three-phase machine-learning pipeline for detecting semantic IoT events from packet metadata, ranking logical device families, and predicting multi-label family/event pairs.

## Notebooks

1. `notebooks/01_data_preparation_eda.ipynb` extracts payload-free PCAP metadata, aligns Eastern label times to UTC, maps hub children to captures, and creates one-second aggregates.
2. `notebooks/02_training_evaluation.ipynb` selects a causal window, trains and evaluates the event gate and joint family/event model, saves deployment artifacts, and documents transfer to another dataset.

Both notebooks have been executed successfully with the `phase34` Conda environment. To rerun them from the project root:

```bash
conda run -n phase34 jupyter nbconvert --to notebook --execute --inplace --ExecutePreprocessor.timeout=-1 notebooks/01_data_preparation_eda.ipynb
conda run -n phase34 jupyter nbconvert --to notebook --execute --inplace --ExecutePreprocessor.timeout=-1 notebooks/02_training_evaluation.ipynb
```

The source dataset is treated as read-only. All packet CSVs, window caches, predictions, figures, and model files are stored under `derived/` and `artifacts/` in this project.

## Reusable inference

`src/iot_pipeline.py` contains the extraction, label, feature, model, evaluation, and `IoTEventPredictor` implementations. The trained bundle is under `artifacts/models/`; its `metadata.json` records the selected window, feature order, ontology, calibration, and thresholds.

The notebooks intentionally report the poor end-to-end future-stream precision instead of presenting only balanced-sample results. The current model is a research baseline and should not be deployed without improving Phase 1 background coverage and false-alarm performance.
