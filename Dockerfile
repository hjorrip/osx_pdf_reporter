FROM python:3.8 

RUN apt-get update && apt-get install -y latexmk && apt-get install -y texlive-latex-extra

<<<<<<< HEAD
RUN mkdir /osxreporter

WORKDIR /osxreporter

RUN git clone https://github.com/hjorrip/osx_pdf_reporter

RUN pip install -r /osxreporter/app/requirements.txt

=======
COPY . /osxreporter

RUN pip install -r /osxreporter/app/requirements.txt

>>>>>>> d8582462e6940a779f4364d165430cc295d2e7f9
CMD ["python", "/osxreporter/app/main.py"]