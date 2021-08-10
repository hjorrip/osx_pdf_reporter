FROM python:3.8 

RUN apt-get update && apt-get install -y latexmk && apt-get install -y texlive-latex-extra

RUN git clone https://github.com/hjorrip/osx_pdf_reporter

WORKDIR /osx_pdf_reporter
RUN echo "#!/bin/bash" >> run.sh
# It's possible to pass inn -v for verbose for the $1 argument
RUN echo "git pull && python /osx_pdf_reporter/app/main.py $1" >> run.sh
RUN chmod +x run.sh

RUN pip install -r /osx_pdf_reporter/app/requirements.txt

ENTRYPOINT ["/osx_pdf_reporter/run.sh"]
