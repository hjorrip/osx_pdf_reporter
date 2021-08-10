FROM python:3.8 

RUN apt-get update && apt-get install -y latexmk && apt-get install -y texlive-latex-extra

RUN git clone https://github.com/hjorrip/osx_pdf_reporter

RUN pip install -r /osx_pdf_reporter/app/requirements.txt

CMD ["python", "/osx_pdf_reporter/app/main.py"]