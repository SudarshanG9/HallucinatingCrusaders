# Use official lightweight Python image
FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory inside the container
WORKDIR /app

# Set PYTHONPATH so python can resolve the soc_analyst package
ENV PYTHONPATH=/app

# Copy python dependencies list
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the application source code and folders
COPY soc_analyst/ /app/soc_analyst/

# Expose the port FastAPI runs on
EXPOSE 8080

# Start the uvicorn server
CMD ["uvicorn", "soc_analyst.api.main:app", "--host", "0.0.0.0", "--port", "8080"]
