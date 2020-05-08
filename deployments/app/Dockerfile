FROM python:3
ADD app/ /app
WORKDIR /app
RUN apt-get update
RUN apt-get install nmap -y
RUN pip install -r requirements.txt
#ENV LISTENONLY=1
CMD python pi-hole-scanner.py
