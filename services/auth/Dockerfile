FROM python:3.14-slim-bookworm AS dependencies

WORKDIR /build

COPY requirements.txt ./

RUN pip install --no-cache-dir --target=/packages -r requirements.txt

FROM python:3.14-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /service

COPY --from=dependencies /packages /usr/local/lib/python3.14/site-packages

COPY --chown=10002:10002 app ./app

USER 10002:10002

CMD [ "python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]