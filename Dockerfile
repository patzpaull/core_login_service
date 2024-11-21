FROM python:3.12-slim


# Set env variables 
ENV PYTHINDONTWRITENBYTECODE=1
ENV PYTHONBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["fastapi", "run", "main.py"]