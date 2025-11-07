# Explainity

Explainity é uma plataforma web onde estudantes encontram e compartilham vídeos-curtos explicando matérias. O projeto usa Flask 3, SQLAlchemy 2 e SQLite.

## Features
- Cadastro, login e sessão lembrada (Flask-Login).
- Upload seguro de vídeos (auto-normalizados para MP4 H.264 apenas quando necessário) de até 5 GB por padrão, parametrizável via `MAX_CONTENT_LENGTH_MB`.
- Criação de recortes (start/end) sem reprocessar o arquivo; o player respeita os recortes via JavaScript.
- Página inicial com filtros por matéria, nível e busca textual (ilike).
- Interface responsiva e acessível (HTML5, CSS custom, WAI-ARIA).
- Rate-limiting simples e exclusão segura de vídeos publicados.
- CLI `flask --app app init-db` para bootstrap do banco.
- Testes de fumaça com pytest (`tests/test_routes.py`).

## Pré-requisitos
- Python 3.11+
- Virtualenv (`python -m venv .venv`)

## Setup rápido
```powershell
cd C:\Users\Home\Desktop\vscode
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r explainity\requirements.txt
cp explainity\.env.example explainity\.env  # em Windows: Copy-Item
```

## Execução local
```powershell
cd explainity
flask --app app run
# ou
python app.py
```
Acesse `http://127.0.0.1:5000/`.

## Estrutura
```
explainity/
├─ app.py              # App Flask completo
├─ config.py           # Configurações centrais
├─ requirements.txt    # Dependências
├─ templates/          # Jinja2 templates
├─ static/             # CSS e JS
├─ uploads/            # Vídeos enviados (criado em runtime)
├─ instance/           # Banco SQLite (runtime)
└─ tests/              # Testes pytest
```

## Deploy
1. Ajuste `SECRET_KEY`, `DATABASE_URI` e `UPLOAD_FOLDER` em variáveis de ambiente.
2. Rode `flask --app app init-db` no target.
3. Use um servidor WSGI (Gunicorn ou Waitress) atrás de Nginx/Apache.
4. Configure HTTPS e um storage externo para vídeos em produção (veja variáveis `S3_*`, `FORCE_TRANSCODE_MP4`, `FFMPEG_*`).

## Tests
```powershell
.\.venv\Scripts\Activate.ps1
cd explainity
python -m pytest
```

## Licença
Defina a licença conforme necessário.
