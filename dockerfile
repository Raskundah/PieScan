# Use lightweight Python image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install dependencies first (for layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the files
COPY scanner.py .
COPY known_nalware_hashes.txt .  # Optional default hash list
COPY .env .              # Optional for pre-configured API key

# Volume for scanning host directories
VOLUME /scandir

# Entrypoint with default arguments
ENTRYPOINT ["python", "scanner.py", "/scandir"]
CMD ["--vt-check"]