FROM python:3.12-slim

WORKDIR /app

COPY server/ ./server/

RUN pip install --no-cache-dir -r server/requirements.txt

EXPOSE 5000

CMD ["gunicorn", "-b", "0.0.0.0:5000", "--workers", "1", "server.app:create_app()"]
