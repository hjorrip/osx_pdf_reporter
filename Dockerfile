FROM python:3.8 

RUN apt-get update && apt-get install -y latexmk && apt-get install -y texlive-latex-extra

RUN git clone https://github.com/hjorrip/osx_pdf_reporter

RUN chmod +x /osx_pdf_reporter/run.sh

RUN pip install -r /osx_pdf_reporter/app/requirements.txt

CMD ["/osx_pdf_reporter/run.sh"]