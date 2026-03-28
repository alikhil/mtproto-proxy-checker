FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml /app/
RUN pip install --no-cache-dir 'telethon>=1.36'

COPY checker.py mtproto_faketls.py /app/

RUN useradd -m -u 1000 checker && \
    chown -R checker:checker /app

USER checker

ENV PYTHONUNBUFFERED=1

CMD ["python3", "/app/checker.py"]
