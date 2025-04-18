# Base image - lightweight Python 3.9
FROM python:3.9-slim

# Set working directory inside container
WORKDIR /app

# Copy requirements first (for Docker layer caching optimization)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all Python files and hash list
COPY scanner.py .
COPY known_malware_hashes.txt .  
# Default hash list (optional)

# Create mount point for scanning host directories
VOLUME /scandir

# Run as non-root user for security
RUN useradd -m scanner && chown -R scanner:scanner /app
USER scanner

# Default command (can be overridden at runtime)
ENTRYPOINT ["python", "scanner.py", "/scandir"]