# proyectoFinalLC
## Tecnologías utilizadas
- Python 3.10+
- FastAPI
- Cryptography
- Uvicorn

## Estructura del proyrcto
<img width="363" height="452" alt="Captura de pantalla 2025-12-01 112943" src="https://github.com/user-attachments/assets/26c42766-b3a2-45b2-b5e7-97efabef6c9e" />
## como ejecutar el proyecto:
1. Crea un entorno virtual:
   ```bash
   python -m venv venv
2. actívalo
   ```bash
   venv\Scripts\activate
3. Instalar dependencias
   ```bash
   pip install -r requirements.txt
4. Ejecutar servidor:
   ```bash
   uvicorn app.main:app --reload
5. Y abre en el navegador lo siguiente:
   http://127.0.0.1:8000/docs
