FROM python:3.13

WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt
COPY app .
EXPOSE 80
ENV IS_IN_DOCKER=true


RUN python ./db/init_tables.py

CMD ["uvicorn", "main:app", "--proxy-headers", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
