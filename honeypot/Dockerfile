FROM python:3.11-slim

WORKDIR /app

RUN pip install paramiko

RUN pip install paramiko requests

COPY honeypot.py logger.py ./

# Create logs directory
RUN mkdir -p /app/logs

EXPOSE 2222

CMD ["python", "-u", "honeypot.py"]
