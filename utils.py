
import re
import joblib

# Load trained model
model = joblib.load('model/best_insider_model.pkl')

# Text preprocessing
def preprocess_text(text):
    text = text.lower()
    text = re.sub(r"\[.*?\]", "", text)
    text = re.sub(r"[^a-z0-9 ]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

# Inference helper
def classify_log(log_str):
    clean = preprocess_text(log_str)
    pred = model.predict([clean])[0]
    proba = model.predict_proba([clean])[0][pred]
    return {'raw': log_str, 'label': 'Insider Threat' if pred==1 else 'Benign', 'confidence': proba}

# Real-time log monitoring via watchdog
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class LogHandler(FileSystemEventHandler):
    def __init__(self, filepath, buffer):
        self.filepath = filepath
        self.buffer = buffer
        with open(self.filepath, 'r') as f:
            f.seek(0, 2)
            self.position = f.tell()

    def on_modified(self, event):
        if event.src_path == self.filepath:
            with open(self.filepath, 'r') as f:
                f.seek(self.position)
                for line in f:
                    self.buffer.append(line)
                self.position = f.tell()