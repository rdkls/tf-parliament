FROM python:3.7.6-alpine3.10
WORKDIR /bin
COPY * /bin/
RUN pip install -r requirements.txt
RUN mkdir -p /github/workspace/
WORKDIR /github/workspace/
ENTRYPOINT ["/bin/tf-parliament.py"]
CMD ["."]
