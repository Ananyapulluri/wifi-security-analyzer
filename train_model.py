# train_model.py
import pandas as pd
import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
import pickle

# Load dataset
df = pd.read_csv("wifi_dataset.csv")

features = ["signal", "auth_encoded", "duplicate_ssid",
            "randomized_mac", "network_type", "signal_spike"]

X = df[features]

# Scale features (important for K-Means — uses distance)
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train K-Means with 2 clusters (Safe and Malicious)
kmeans = KMeans(n_clusters=2, random_state=42, n_init=10)
kmeans.fit(X_scaled)

# Figure out which cluster is malicious
# Malicious cluster will have higher avg of: open auth, duplicate SSID, randomized MAC
df["cluster"] = kmeans.labels_
cluster_summary = df.groupby("cluster")[["auth_encoded", "duplicate_ssid",
                                          "randomized_mac", "signal_spike"]].mean()
print("\nCluster Summary:")
print(cluster_summary)

# The malicious cluster has LOWER auth_encoded (more open/wep)
# and HIGHER duplicate_ssid and randomized_mac
# Identify which cluster number is malicious
c0 = cluster_summary.loc[0, "duplicate_ssid"] + cluster_summary.loc[0, "randomized_mac"]
c1 = cluster_summary.loc[1, "duplicate_ssid"] + cluster_summary.loc[1, "randomized_mac"]
malicious_cluster = 0 if c0 > c1 else 1
print(f"\nMalicious cluster identified as: Cluster {malicious_cluster}")

# Save model, scaler, and malicious cluster label
pickle.dump(kmeans,           open("kmeans_model.pkl",    "wb"))
pickle.dump(scaler,           open("scaler.pkl",          "wb"))
pickle.dump(malicious_cluster,open("malicious_cluster.pkl","wb"))

print("Model saved → kmeans_model.pkl")
print("Scaler saved → scaler.pkl")
