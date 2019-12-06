FROM python:3.7-alpine

RUN adduser -D user

WORKDIR /home/user

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
COPY . .

RUN chown -R user:user .
USER user

CMD ["flask", "run", "--host=0.0.0.0"]
