"""Pure ONNX GLiNER span-NER runner; no PyTorch or gliner dependency."""
from __future__ import annotations
import json, logging, re, warnings
from pathlib import Path
import numpy as np
import onnxruntime as ort
from huggingface_hub import hf_hub_download
from tokenizers import Tokenizer

logging.getLogger("huggingface_hub").setLevel(logging.ERROR)
warnings.filterwarnings("ignore", category=UserWarning, module="huggingface_hub")

WORD_RE = re.compile(r"\w+(?:[-_]\w+)*|\S")


def _fetch_file(model_id: str, filename: str) -> str:
    """Resolve from the local HF cache first, only hitting the network on a miss."""
    try:
        return hf_hub_download(model_id, filename=filename, local_files_only=True)
    except Exception:
        return hf_hub_download(model_id, filename=filename)


class OnnxGLiNER:
    """Loads onnx-community/gliner_small-v2.1 and exposes predict_entities()."""

    def __init__(self, model_id: str = "onnx-community/gliner_small-v2.1",
                 model_file: str = "onnx/model.onnx") -> None:
        self.model_id = model_id
        self.tokenizer = Tokenizer.from_file(_fetch_file(model_id, "tokenizer.json"))
        config = json.loads(Path(_fetch_file(model_id, "gliner_config.json")).read_text(encoding="utf-8"))
        self.max_width = int(config.get("max_width", 12))
        self.cls_id = self.tokenizer.token_to_id("[CLS]") or 1
        self.sep_id = self.tokenizer.token_to_id("[SEP]") or 2
        self.ent_id = self.tokenizer.token_to_id("<<ENT>>") or 128002
        self.psep_id = self.tokenizer.token_to_id("<<SEP>>") or 128003
        available = ort.get_available_providers()
        providers = [p for p in ("CUDAExecutionProvider", "CPUExecutionProvider") if p in available]
        self.provider = providers[0] if providers else "CPUExecutionProvider"
        self.session = ort.InferenceSession(
            _fetch_file(model_id, model_file),
            providers=providers or ["CPUExecutionProvider"],
        )

    def _encode(self, word: str) -> list[int]:
        return self.tokenizer.encode([word], is_pretokenized=True, add_special_tokens=False).ids

    def predict_entities(self, text: str, labels: list[str], threshold: float = 0.5,
                         flat_ner: bool = True) -> list[dict]:
        words = [(m.group(), m.start(), m.end()) for m in WORD_RE.finditer(text)]
        if not words or not labels:
            return []

        input_ids, words_mask = [self.cls_id], [0]
        for label in labels:
            input_ids.append(self.ent_id); words_mask.append(0)
            sub = self._encode(str(label))
            input_ids.extend(sub); words_mask.extend([0] * len(sub))
        input_ids.append(self.psep_id); words_mask.append(0)
        for word_id, (word, _, _) in enumerate(words, 1):
            sub = self._encode(word)
            input_ids.extend(sub)
            words_mask.extend([word_id] + [0] * (len(sub) - 1))
        input_ids.append(self.sep_id); words_mask.append(0)

        n = len(words)
        span_idx = np.zeros((1, n * self.max_width, 2), dtype=np.int64)
        span_mask = np.zeros((1, n * self.max_width), dtype=bool)
        for i in range(n):
            for width in range(self.max_width):
                flat = i * self.max_width + width
                span_idx[0, flat] = (i, min(i + width, n - 1))
                span_mask[0, flat] = i + width < n

        feed = {
            "input_ids": np.array([input_ids], dtype=np.int64),
            "attention_mask": np.ones((1, len(input_ids)), dtype=np.int64),
            "words_mask": np.array([words_mask], dtype=np.int64),
            "text_lengths": np.array([[n]], dtype=np.int64),
            "span_idx": span_idx,
            "span_mask": span_mask,
        }
        logits = self.session.run(None, feed)[0]
        probs = 1.0 / (1.0 + np.exp(-np.clip(logits[0], -50, 50)))

        candidates = []
        for start in range(n):
            for width in range(self.max_width):
                if start + width >= n:
                    continue
                for label_idx in range(probs.shape[2]):
                    score = float(probs[start, width, label_idx])
                    if score >= threshold:
                        candidates.append((score, start, start + width, label_idx))

        selected, used = [], []
        for score, w_start, w_end, label_idx in sorted(candidates, key=lambda item: -item[0]):
            start, end = words[w_start][1], words[w_end][2]
            if flat_ner and any(max(start, a) < min(end, b) for a, b in used):
                continue
            used.append((start, end))
            selected.append({"start": start, "end": end, "text": text[start:end],
                             "label": labels[label_idx], "score": score})
        return sorted(selected, key=lambda item: item["start"])
