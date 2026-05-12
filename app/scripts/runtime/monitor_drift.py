#!/usr/bin/env python3
"""Проверяет дрейф признаков по критерию Колмогорова-Смирнова."""
import numpy as np
from scipy.stats import ks_2samp
import redis, os, json

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
r = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)

# Эталонное распределение (можно загрузить из файла или Redis)
# Здесь для примера возьмём массив из файла, если нет – создадим заглушку.
try:
    ref = np.load("reference_distribution.npy")
except FileNotFoundError:
    print("Эталонное распределение не найдено. Использую заглушку.")
    ref = np.random.normal(0.5, 0.1, 1000)  # заглушка

# Собираем последние N векторов признаков из логов
# В реальной системе они сохраняются в Redis; пока просто эмулируем.
# Для демонстрации возьмём несколько случайных векторов.
current = np.random.normal(0.5, 0.15, 100)  # имитация свежих данных

stat, p_value = ks_2samp(ref, current)
threshold = 0.05
if p_value < threshold:
    print(f"[WARN] Обнаружен дрейф данных! p-value={p_value:.4f}")
    # Здесь может быть вызов алерта или запись в Redis
    r.set("metrics:drift_detected", "true")
else:
    print(f"[OK] Дрейф не обнаружен. p-value={p_value:.4f}")
    r.set("metrics:drift_detected", "false")
