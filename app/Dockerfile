FROM python:3.10

RUN apt-get update
RUN apt-get install -y wait-for-it
RUN pip install waitress
ADD . /app
WORKDIR /app

RUN pip install -r requirements.txt

CMD sh ./entrypoint.sh