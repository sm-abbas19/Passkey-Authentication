FROM python:3.10

RUN apt-get update && \
    apt-get install -y wait-for-it && \
    pip install waitress

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["sh", "./entrypoint.sh"]