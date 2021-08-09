FROM python:3.8 

RUN apt-get update && apt-get install -y latexmk && apt-get install -y texlive-latex-extra

COPY . /osxreporter

RUN pip install -r /osxreporter/app/requirements.txt

CMD ["python", "/osxreporter/app/main.py"]