# dataset_generator.py
import pandas as pd
import numpy as np

np.random.seed(42)
data = []

# Safe networks (600 samples)
for _ in range(600):
    data.append({
        "signal":         np.random.randint(20, 80),
        "auth_encoded":   2,
        "duplicate_ssid": 0,
        "randomized_mac": 0,
        "network_type":   0,
        "signal_spike":   0,
    })

# Malicious networks (400 samples)
for _ in range(400):
    attack = np.random.choice(["evil_twin", "open_rogue", "wep", "adhoc"])
    if attack == "evil_twin":
        data.append({
            "signal":         np.random.randint(50, 99),
            "auth_encoded":   np.random.choice([0, 1, 2]),
            "duplicate_ssid": 1,
            "randomized_mac": np.random.choice([0, 1]),
            "network_type":   0,
            "signal_spike":   np.random.choice([0, 1]),
        })
    elif attack == "open_rogue":
        data.append({
            "signal":         np.random.randint(60, 100),
            "auth_encoded":   0,
            "duplicate_ssid": np.random.choice([0, 1]),
            "randomized_mac": 1,
            "network_type":   0,
            "signal_spike":   np.random.choice([0, 1]),
        })
    elif attack == "wep":
        data.append({
            "signal":         np.random.randint(20, 70),
            "auth_encoded":   3,
            "duplicate_ssid": 0,
            "randomized_mac": 0,
            "network_type":   0,
            "signal_spike":   0,
        })
    elif attack == "adhoc":
        data.append({
            "signal":         np.random.randint(70, 100),
            "auth_encoded":   np.random.choice([0, 1]),
            "duplicate_ssid": 0,
            "randomized_mac": 1,
            "network_type":   1,
            "signal_spike":   1,
        })

df = pd.DataFrame(data)
df.to_csv("wifi_dataset.csv", index=False)
print(f"Dataset created: {len(df)} samples")
print(df.head())
