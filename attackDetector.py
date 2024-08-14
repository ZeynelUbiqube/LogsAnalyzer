# Collecte et Prétraitement des Données
import sys

import numpy as np
import pandas as pd

# Charger les logs (par exemple, un fichier CSV)
df = pd.read_csv(sys.argv[1])

# Afficher les premières lignes pour comprendre la structure
print(df.head())

# Supposons que la colonne 'Label' indique s'il y a une attaque
# Séparons les caractéristiques (features) et les étiquettes (labels)
X = df.drop(columns=[' Label'])
y = df[' Label']

# Afficher les valeurs uniques dans les labels pour comprendre les types d'attaques
print(y.value_counts())

# Prétraitement des Données

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder

# Encoder les labels (transforme les catégories d'attaque en valeurs numériques)
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

# Diviser les données en ensembles d'entraînement et de test
# Sélectionner uniquement les colonnes numériques pour la normalisation
X_numeric = X.select_dtypes(include=['float64', 'int64'])

# Diviser les données en ensembles d'entraînement et de test
X_train, X_test, y_train, y_test = train_test_split(X_numeric, y, test_size=0.3, random_state=42)

# Remplacer les valeurs infinies par un grand nombre (par exemple, la valeur maximale des autres données)
X_train.replace([np.inf, -np.inf], np.nan, inplace=True)
X_test.replace([np.inf, -np.inf], np.nan, inplace=True)

# Remplacer les valeurs manquantes par la moyenne de la colonne
X_train.fillna(X_train.mean(), inplace=True)
X_test.fillna(X_train.mean(), inplace=True)


# Normaliser les colonnes numériques
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Afficher les formes pour vérifier
print(X_train_scaled.shape)
print(X_test_scaled.shape)

# Entraînement d'un Modèle de Détection d'Attaques

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

# Initialiser le modèle
model = RandomForestClassifier(n_estimators=100, random_state=42)

# Entraîner le modèle
model.fit(X_train_scaled, y_train)

# Prédire sur l'ensemble de test
y_pred = model.predict(X_test_scaled)

# Évaluer le modèle
print(confusion_matrix(y_test, y_pred))
print(classification_report(y_test, y_pred))


# Optimisation du Modèle

from sklearn.model_selection import GridSearchCV

# Définir les hyperparamètres à tester
param_grid = {
    'n_estimators': [50, 100, 200],
    'max_depth': [None, 10, 20, 30],
    'min_samples_split': [2, 5, 10],
}

# Recherche de la meilleure combinaison d'hyperparamètres
grid_search = GridSearchCV(estimator=model, param_grid=param_grid, cv=5)
grid_search.fit(X_train_scaled, y_train)

# Meilleurs hyperparamètres trouvés
print(grid_search.best_params_)

# Évaluer le modèle optimisé
best_model = grid_search.best_estimator_
y_pred_optimized = best_model.predict(X_test_scaled)
print(classification_report(y_test, y_pred_optimized))


# Déploiement et Détection en Temps Réel

def detect_attack(log_entry):
    # Prétraiter la nouvelle entrée de log comme les données d'entraînement
    log_entry_scaled = scaler.transform([log_entry])

    # Prédire avec le modèle
    prediction = best_model.predict(log_entry_scaled)

    # Retourner le type d'attaque ou "Benign"
    return label_encoder.inverse_transform(prediction)[0]

# Exemple d'utilisation
new_log = X_test.iloc[0]  # Prenons une entrée de test comme exemple
result = detect_attack(new_log)
print(f"Résultat de la détection : {result}")
