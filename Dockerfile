FROM python:3.11-alpine

WORKDIR /app

# Copy the dependency file and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of application
COPY . .

EXPOSE 1337

CMD ["gunicorn", "-c", "gunicorn.conf.py", "owa_pot:app"]
