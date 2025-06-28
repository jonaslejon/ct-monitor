# Use an official lightweight Python image
FROM python:3.12-alpine

# Set the working directory in the container
WORKDIR /app

# Create a non-privileged user
RUN addgroup -S appuser && adduser -S -G appuser -s /bin/false -D appuser

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application script
COPY ct-monitor.py .

# Make the script executable
RUN chmod +x ct-monitor.py

# Change ownership to the new user
RUN chown -R appuser:appuser /app

# Switch to the non-privileged user
USER appuser

# Set the entrypoint for the container
ENTRYPOINT ["python3", "./ct-monitor.py"]

# Set default command to show help
CMD ["--help"]
