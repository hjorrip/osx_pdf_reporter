FROM python:3.8

RUN apt-get update && apt-get install -y latexmk && apt-get install -y texlive-latex-extra

COPY . .

RUN pip install -r /app/requirements.txt

CMD ["python", "/app/main.py"]