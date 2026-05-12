import hashlib
import json
import re
from datetime import datetime
from typing import Dict, List, Tuple
import pandas as pd
import numpy as np

class APIDatasetPipeline:
    def __init__(self, normal_train_ratio: float = 0.70, normal_val_ratio: float = 0.15):
        self.normal_train_ratio = normal_train_ratio
        self.normal_val_ratio = normal_val_ratio
        # Регулярные выражения для токенизации
        self.re_num = re.compile(r'\b\d+\b')
        self.re_str = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}|(?:https?://|www\.)[^\s]+')
        self.re_uuid = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)
        self.re_uri_id = re.compile(r'/\d+')

    def _normalize_service_symbols(self, text: str) -> str:
        """ТЗ 3.4: Детерминированная нормализация служебных символов перед хэшированием"""
        return re.sub(r'\s+', ' ', str(text).strip().lower())

    def compute_integrity_hash(self, record: Dict) -> str:
        """ТЗ 3.4: SHA-256 хэш для верификации целостности (вместо MD5)"""
        payload = f"{record.get('http_method', '')}|{record.get('uri_path', '')}|{record.get('timestamp', '')}"
        payload = self._normalize_service_symbols(payload)
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()

    def tokenize_text(self, text: str) -> str:
        """ТЗ 1.1: Абстракция конкретных значений в теле запроса"""
        if pd.isna(text) or text is None: return ""
        text = str(text)
        text = self.re_str.sub('STR', text)
        text = self.re_uuid.sub('ID', text)
        text = self.re_num.sub('NUM', text)
        return text

    def normalize_uri(self, uri: str) -> str:
        """ТЗ 1.1: Замена идентификаторов в URI на {ID}"""
        return self.re_uri_id.sub('/{ID}', str(uri))

    def extract_behavioral(self, session_logs: List[Dict]) -> Dict[str, float]:
        """ТЗ 1.1: Вычисление поведенческих метрик сессии"""
        if len(session_logs) < 2:
            return {'req_freq': 0.0, 'unique_endpoints': 0.0, 'mean_interval_sec': 0.0}
        try:
            timestamps = sorted([datetime.fromisoformat(r['timestamp']) for r in session_logs])
            intervals = [(timestamps[i] - timestamps[i-1]).total_seconds() for i in range(1, len(timestamps))]
            unique_eps = len(set(r['uri_path'] for r in session_logs))
            duration = (timestamps[-1] - timestamps[0]).total_seconds() or 1.0
            return {
                'req_freq': len(session_logs) / duration,
                'unique_endpoints': float(unique_eps),
                'mean_interval_sec': float(np.mean(intervals))
            }
        except Exception:
            return {'req_freq': 0.0, 'unique_endpoints': 0.0, 'mean_interval_sec': 0.0}

    def build_feature_vector(self, raw_record: Dict, behavioral_metrics: Dict) -> Dict:
        """Формирование вектора x = {x₁...xᴰ}. КОНТУР ИЗОЛИРОВАН ОТ SAST/DAST (ТЗ 3.1)"""
        processed = raw_record.copy()
        processed['uri_path'] = self.normalize_uri(processed['uri_path'])
        if 'request_body' in processed and processed['request_body']:
            try:
                body_str = json.dumps(processed['request_body'], ensure_ascii=False)
            except:
                body_str = str(processed['request_body'])
            processed['request_body'] = self.tokenize_text(body_str)

        processed.update(behavioral_metrics)
        processed['event_id'] = self.compute_integrity_hash(raw_record)


        for key in ['cvss', 'vulnerability_weight', 'sast_report', 'dast_exploitable', 'V_e']:
            processed.pop(key, None)
        return processed

    def split_dataset_one_class(self, normal_df: pd.DataFrame, anomaly_df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """ТЗ 3.1: Одноклассовая парадигма. Обучение ТОЛЬКО на норме."""
        n_norm = len(normal_df)
        train_size = int(n_norm * self.normal_train_ratio)
        val_size = int(n_norm * self.normal_val_ratio)

        train_norm = normal_df.iloc[:train_size].copy()
        val_norm = normal_df.iloc[train_size:train_size+val_size].copy()
        test_norm = normal_df.iloc[train_size+val_size:].copy()

        n_anom = len(anomaly_df)
        half_anom = n_anom // 2
        val_anom = anomaly_df.iloc[:half_anom].copy()
        test_anom = anomaly_df.iloc[half_anom:].copy()

        train_df = pd.concat([train_norm], ignore_index=True)
        val_df = pd.concat([val_norm, val_anom], ignore_index=True)
        test_df = pd.concat([test_norm, test_anom], ignore_index=True)
        return train_df, val_df, test_df
