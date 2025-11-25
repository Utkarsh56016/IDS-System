import numpy as np
import pickle

# Load ML components
model = pickle.load(open("model.pkl", "rb"))
scaler = pickle.load(open("scaler.pkl", "rb"))
threshold = pickle.load(open("threshold.pkl", "rb"))

def model_predict_flow(feature_vector):
    """
    Takes a 37-dimensional flow feature vector,
    scales it, runs ML inference, and returns:
      → score (float)
      → is_anomaly (bool)
    """
    fv = np.array(feature_vector).reshape(1, -1)

    # Scale
    scaled = scaler.transform(fv)

    # Compute anomaly score
    score = -model.decision_function(scaled)[0]

    # Compare with threshold
    is_anomaly = score > threshold

    return score, is_anomaly
