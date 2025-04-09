# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /app

# Install system dependencies if needed (e.g., for psycopg2)
# RUN apt-get update && apt-get install -y --no-install-recommends \
#     build-essential libpq-dev \
#  && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy the requirements file into the container
COPY requirements.txt requirements.txt

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
# Note: .dockerignore ensures instance/, .env, .git/ etc. are NOT copied
COPY . .

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Define the command to run the app using Gunicorn
# Bind to 0.0.0.0 to allow external connections
# 'app:app' assumes your Flask application instance is named 'app' in 'app.py'
# You might need to adjust the number of workers (-w)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "-w", "4", "app:app"]
