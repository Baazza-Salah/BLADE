
---

# BLADE

Welcome to BLADE, a project aimed at enabling real‑time Insider Threat Behavior Analysis and Prediction based on Linux system logs. This repository combines the power of Jupyter Notebooks, Python, and Streamlit to ingest, visualize, and classify log entries—helping security teams detect suspicious activity swiftly.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)


## Overview

BLADE is designed to monitor Linux log files (e.g. /var/log/auth.log) in real time, preprocess each entry, and apply a trained machine‑learning model to classify events as Benign or Insider Threat. It provides both:
  - Interactive Jupyter Notebooks for exploratory data analysis and model training.
  - A Streamlit web app for live dashboards and ad‑hoc log classification.

By leveraging TF‑IDF text encoding, scikit‑learn pipelines, and real‑time file monitoring, BLADE makes it straightforward to spot anomalous user behavior and privilege‑escalation attempts.

## Features

- Real‑time Log Monitoring: Watches specified log files for new entries and classifies them on the fly.
- Data Visualizations: Interactive charts (pie, histograms, ROC curves) to summarize benign vs. threat events.
- Ad‑hoc Classification: Paste or upload individual log lines to see immediate predictions and confidence scores.
- Jupyter Notebooks: Fully documented notebooks for data cleaning, model evaluation, and hyperparameter tuning.
- Model Persistence: Uses a best_insider_model.pkl to load pre‑trained pipelines without retraining.

## Getting Started

Follow the instructions below to set up the project locally and get started.

### Prerequisites

Ensure you have the following installed on your system:

- **Python** (3.7 or later)
- **Jupyter Notebook**

### Installation

1. Clone this repository to your local machine:

   ```bash
   git clone https://github.com/Baazza-Salah/BLADE.git
   cd BLADE
   ```

2. Create and activate a virtual environment (optional but recommended):

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Jupyter Notebooks

To start using BLADE:

1. Launch Jupyter Notebook:

   ```bash
   jupyter notebook
   ```

2. Open the relevant notebook(s) from the repository to explore and run the code.

### Streamlit Web App

To start using BLADE:

1. Ensure your trained model best_insider_model.pkl is placed under model/.

2. Run the Streamlit app:

   ```bash
   streamlit run app.py
   ```
3. Use the sidebar to switch between:
   - Logs Dashboard: real‑time monitoring and pie‑chart summaries.
   - Test Model: manual classification of custom log lines.


This project is licensed under the [insert license type, e.g., MIT License]. See the `LICENSE` file for more details.

---

Feel free to update the placeholders (e.g., project purpose, features, license type) with more specific details about your project. Let me know if you'd like assistance with customizing this further!
