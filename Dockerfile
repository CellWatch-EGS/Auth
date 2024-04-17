# Use an official Python runtime as a parent image
FROM python:3.9-slim

LABEL maintainer="Rodrigues"

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# esperar pelo container a correr
COPY wait-for-it.sh /wait-for-it.sh

RUN chmod +x /wait-for-it.sh

# Install any needed dependencies specified in requirements.txt
RUN pip install -r requirements.txt
# RUN pip install python-dotenv

# Make port 8080 available to the world outside this container
EXPOSE 8080/tcp

# Run the Flask application
CMD ["python3", "run.py"]
