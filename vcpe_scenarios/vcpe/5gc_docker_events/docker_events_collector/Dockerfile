FROM python:2.7.16-stretch

COPY . /docker_events_notifier

WORKDIR /docker_events_notifier

RUN pip install -r requirements.txt

RUN python -m pip install .

ENTRYPOINT ["/usr/local/bin/docker-events", "-c", "consumers.yaml", "-m", "docker_notifier.notify"]

CMD ["-s", "127.0.0.1:2375"]
