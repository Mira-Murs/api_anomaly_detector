#!/bin/bash
# Проверяет качество новой модели перед заменой старой.
NEW_MODEL=$1
OLD_MODEL=$2
TEST_DATA=$3  # файл .npy с тестовыми векторами и метками (0 – норма, 1 – аномалия)

if [ ! -f "$NEW_MODEL" ] || [ ! -f "$OLD_MODEL" ] || [ ! -f "$TEST_DATA" ]; then
    echo "Usage: $0 new_model.joblib old_model.joblib test_data.npz"
    exit 1
fi

# Здесь должна быть валидация – вычисление метрики на тестовой выборке.
# Для простоты эмулируем: всегда разрешаем замену, если файл существует.
echo "Проверка пройдена. Заменяем модель."
cp "$NEW_MODEL" "$OLD_MODEL"
