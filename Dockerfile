FROM python:3.7-alpine

RUN adduser -D user

WORKDIR /home/user

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
COPY . .


ENV FLASK_APP app.py
RUN chown -R user:user .
USER user

expose 8080
CMD ["flask", "run", "--host=0.0.0.0"]
