# LogsAnalyzer - Détection d'Attaques à partir des Logs Réseau

## Description
`LogsAnalyzer` est un projet d'analyse des logs réseau pour la détection d'attaques, en particulier les attaques par déni de service distribué (DDoS). Ce projet utilise des algorithmes d'apprentissage automatique, principalement RandomForest, pour classifier les flux de données comme étant bénins ou malveillants.

## Prérequis

Avant de commencer, assurez-vous d'avoir installé les dépendances nécessaires :

- Python 3.8+
- Les bibliothèques Python suivantes :
  - `scikit-learn`
  - `pandas`
  - `numpy`

Vous pouvez installer ces dépendances avec `pip` :

```bash
pip install scikit-learn pandas numpy
```
## Utilisation
```bash
python attackDetector.py fileName.csv
```
