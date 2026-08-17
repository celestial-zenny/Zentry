FROM python:3.12-slim

WORKDIR /app

# Dependencies first, so code edits don't invalidate the pip layer.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 7860 is the port Hugging Face Spaces expects; Render, Fly and Railway all
# inject their own $PORT instead.
ENV PORT=7860
EXPOSE 7860

CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-7860}"]
