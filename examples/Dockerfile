FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
ENV OPENAI_API_KEY=sk-proj-demoNotARealKeyJustAnExample1234567890
CMD ["uvicorn", "vulnerable_app:app", "--host", "0.0.0.0"]
