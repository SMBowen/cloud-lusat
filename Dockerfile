FROM python:alpine

COPY src/ /src
WORKDIR /src

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "lusat.py"]
