FROM python:3.14-slim-bookworm AS dependencies

WORKDIR /build

COPY requirements.txt ./

RUN pip install \
    --no-cache-dir \
    --target=/packages \
    -r requirements.txt


FROM python:3.14-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /service

COPY --from=dependencies \
    /packages \
    /usr/local/lib/python3.14/site-packages

COPY --chown=10001:10001 app ./app

USER 10001:10001

CMD [ "python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000" ]