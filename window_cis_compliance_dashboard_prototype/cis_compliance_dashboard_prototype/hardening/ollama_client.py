"""Fixed loopback-only Ollama client with time/size limits and no cloud fallback."""

import http.client
import json
import time


class OllamaClient:
    model = "qwen3:8b"
    provenance = "Local Ollama"

    def __init__(self, num_predict=384):
        if type(num_predict) is not int or not 64 <= num_predict <= 2048:
            raise ValueError("num_predict must be between 64 and 2048 tokens")
        self.num_predict = num_predict

    def chat(self, messages, tools, *, timeout):
        deadline = time.monotonic() + timeout
        payload = json.dumps({"model": self.model, "messages": messages, "tools": tools,
                              "stream": False, "think": False, "keep_alive": "5m",
                              "options": {"temperature": 0, "num_predict": self.num_predict, "num_ctx": 4096}}).encode()
        connection = http.client.HTTPConnection("127.0.0.1", 11434, timeout=timeout)
        try:
            connection.connect()
            active_socket = connection.sock
            active_socket.settimeout(max(0.01, deadline - time.monotonic()))
            connection.request("POST", "/api/chat", body=payload, headers={"Content-Type": "application/json"})
            active_socket.settimeout(max(0.01, deadline - time.monotonic()))
            response = connection.getresponse()
            if response.status != 200:
                raise ValueError(f"Ollama HTTP status {response.status}")
            chunks, size = [], 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Ollama response exceeded request deadline")
                active_socket.settimeout(remaining)
                chunk = response.read1(8192)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > 262144:
                    raise ValueError("Ollama response exceeds size limit")
            data = json.loads(b"".join(chunks))
            if not isinstance(data, dict) or not isinstance(data.get("message"), dict):
                raise ValueError("Invalid Ollama response")
            # Never persist or feed raw thinking back into the application.
            message = data["message"]
            return {"role": "assistant", "content": message.get("content", ""),
                    "tool_calls": message.get("tool_calls", [])}
        finally:
            connection.close()


def model_available(timeout=1.0):
    """Loopback check for the status panel: is Ollama up and is the agents' model pulled?"""
    connection = http.client.HTTPConnection("127.0.0.1", 11434, timeout=timeout)
    try:
        connection.request("GET", "/api/tags")
        response = connection.getresponse()
        if response.status != 200:
            return False
        models = json.loads(response.read(4194304)).get("models", [])
        return any(m.get("name") == OllamaClient.model for m in models if isinstance(m, dict))
    except (OSError, ValueError, AttributeError):
        return False
    finally:
        connection.close()
