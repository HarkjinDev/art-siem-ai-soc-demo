FROM python:3.12-slim
WORKDIR /app
COPY slack/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY slack/bot.py /app/bot.py
RUN useradd --create-home --uid 10001 soc
USER soc
CMD ["python", "-u", "bot.py"]
