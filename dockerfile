# Dockerfile, Image, Container
FROM python:alpine

ADD scanner.py .

RUN pip install requests dotenv

# CMD ["python", "scanner.py"]

ENTRYPOINT ["python","./scanner.py"]
