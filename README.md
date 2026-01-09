SAE 1.05 — Traiter les Données

[FR]
Application Flask qui analyse une sortie texte de tcpdump, génère un rapport (Markdown → HTML) avec graphes, et permet d’exporter les résultats en CSV (ZIP) et Excel (XLSX).

LANCER AVEC LE .EXE (Windows)
- Exécuter app.exe (double-clic ou via terminal).
- Ouvrir ensuite le navigateur sur http://127.0.0.1:5000/

LANCER AVEC PYTHON
1) Installer Python 3.10+ sur le système.
2) Ouvrir un terminal dans le dossier du projet (là où se trouve app.py).
3) (Optionnel) Créer et activer un environnement virtuel.
4) Installer les dépendances :
   pip install flask markdown matplotlib openpyxl
5) Lancer l’application :
   python app.py
6) Ouvrir le navigateur sur : http://127.0.0.1:5000/

[EN]
Flask web app that analyzes a text tcpdump output, generates a report (Markdown → HTML) with charts, and exports results to CSV (ZIP) and Excel (XLSX).

RUN USING THE .EXE (Windows)
- Run app.exe (double-click or from a terminal).
- Then open your browser at http://127.0.0.1:5000/

RUN USING PYTHON
1) Install Python 3.10+ on your system.
2) Open a terminal in the project directory (where app.py is located).
3) (Optional) Create and activate a virtual environment.
4) Install dependencies:
   pip install flask markdown matplotlib openpyxl
5) Launch the application:
   python app.py
6) Open your browser at: http://127.0.0.1:5000/ 
