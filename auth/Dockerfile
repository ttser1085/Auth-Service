FROM python:3.12-slim

WORKDIR /practice-security/auth

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

ENTRYPOINT ["python", "-m", "main"]
