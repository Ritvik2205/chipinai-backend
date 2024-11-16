FROM python:3.9-slim

ENV PYTHONUNBUFFERED 1

RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    libtesseract-dev \
    libpq-dev \
    build-essential \
    gcc \
    libgl1-mesa-glx \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


RUN mkdir /app
WORKDIR /app

COPY requirements.txt /app/

RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/

EXPOSE 8080

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "server:app"]