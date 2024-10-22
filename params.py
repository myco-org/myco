import numpy as np
import matplotlib.pyplot as plt

# Constants
Z = 100  # bucket capacity
x = 10**6  # total number of messages
y = 10**6  # sampled paths
D = 30  # maximum depth
deltaExp = 1000  # set DeltaExp (adjust as needed)

# Define depth range
depths = np.arange(0, D+1)

# Function to calculate p_v(ky)
def p_v_ky(d, k, y):
    term1 = (1 - 2.0**-(d + 1))**(k * y)
    term2 = (1 - 2.0**-d)**(k * y)
    return 2.0**-d * (term1 - term2)

# Function to calculate E[B_{deltaExp, v}]
def expected_B(deltaExp, d, x, y):
    return x * np.sum([p_v_ky(d, k, y) for k in range(1, deltaExp + 1)])

# Chernoff bound probability function
def chernoff_bound_p(X_v, Z, x_pv):
    delta = Z / x_pv - 1
    return np.exp(- ((delta**2) / (2 + delta)) * x_pv)

# Recalculate expected B values for DeltaExp
expected_B_values = np.array([expected_B(deltaExp, d, x, y) for d in depths], dtype=float)

# Recalculate Chernoff bound probabilities
chernoff_probabilities = chernoff_bound_p(Z, Z, expected_B_values)

# Find and print the maximum probability and its corresponding depth
max_probability = np.max(chernoff_probabilities)
max_depth = depths[np.argmax(chernoff_probabilities)]
print(f"Maximum Probability: {max_probability} at Depth: {max_depth}")

# Plot the result
plt.figure(figsize=(10, 6))
plt.plot(depths, chernoff_probabilities, label=f'Probability for DeltaExp={deltaExp}')
plt.yscale('log')  # Use log scale for y-axis as the probabilities are very small
plt.xlabel('Depth (d)')
plt.ylabel('Probability of Exceeding Capacity Z')
plt.title(f'Probability of Exceeding Capacity Z vs Depth d for DeltaExp = {deltaExp}')
plt.grid(True)
plt.legend()
plt.show()
