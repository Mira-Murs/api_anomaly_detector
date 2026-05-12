import joblib
import hashlib
import json
from pathlib import Path

class ModelLoader:
    def __init__(self, model_path):
        self.model_path = Path(model_path)
        self.model = None

    def load(self):
        if not self.model_path.exists():
            raise FileNotFoundError(f"Model not found: {self.model_path}")
        hash_path = self.model_path.with_suffix(".hash")
        if hash_path.exists():
            with open(hash_path) as f:
                expected = json.load(f)["hash"]
            with open(self.model_path, "rb") as f:
                actual = hashlib.sha256(f.read()).hexdigest()
            if actual != expected:
                raise RuntimeError("Model hash mismatch")
        self.model = joblib.load(self.model_path)
        return self.model

    def get_model(self):
        if self.model is None:
            self.load()
        return self.model
