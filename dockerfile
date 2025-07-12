# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /code

# Copy the requirements file and install dependencies
COPY ./requirements.txt /code/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

# Copy the application code
COPY ./app.py /code/app.py

# Expose the port the app runs on
EXPOSE 8000

# Command to run the application using uvicorn
# The --host 0.0.0.0 is crucial for Render to bind to the container.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
