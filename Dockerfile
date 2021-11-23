FROM python

COPY ./requirements.txt /home/myapp/requirements.txt
RUN pip install -r /home/myapp/requirements.txt
COPY api.py /home/myapp/
COPY db_init.py /home/myapp/
EXPOSE 5000
RUN python3 /home/myapp/db_init.py
CMD python3 /home/myapp/api.py