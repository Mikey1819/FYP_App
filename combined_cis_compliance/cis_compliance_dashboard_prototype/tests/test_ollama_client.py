"""HTTP protocol tests mock loopback transport; no model calls."""

import json
import unittest
from unittest.mock import Mock, patch

from hardening.ollama_client import OllamaClient


class OllamaClientTests(unittest.TestCase):
    def connection(self, body, status=200):
        response = Mock(status=status)
        response.read1.side_effect = [body, b""]
        connection = Mock()
        connection.getresponse.return_value = response
        return connection

    def test_fixed_local_request_and_thinking_is_removed(self):
        connection = self.connection(json.dumps({"message": {"content": "Done", "thinking": "private"}}).encode())
        with patch("hardening.ollama_client.http.client.HTTPConnection", return_value=connection) as factory:
            result = OllamaClient().chat([], [], timeout=10)
        factory.assert_called_once_with("127.0.0.1", 11434, timeout=10)
        request = json.loads(connection.request.call_args.kwargs["body"])
        self.assertEqual(request["model"], "qwen3:8b")
        self.assertFalse(request["think"])
        self.assertFalse(request["stream"])
        self.assertNotIn("thinking", result)
        connection.close.assert_called_once()

    def test_http_error_and_malformed_response_close_connection(self):
        for body, status in ((b"bad", 500), (b"not json", 200), (b"{}", 200)):
            connection = self.connection(body, status)
            with patch("hardening.ollama_client.http.client.HTTPConnection", return_value=connection):
                with self.assertRaises(ValueError):
                    OllamaClient().chat([], [], timeout=10)
            connection.close.assert_called_once()

    def test_oversized_response_is_rejected(self):
        connection = self.connection(b"x" * 262145)
        with patch("hardening.ollama_client.http.client.HTTPConnection", return_value=connection):
            with self.assertRaisesRegex(ValueError, "size limit"):
                OllamaClient().chat([], [], timeout=10)
        connection.close.assert_called_once()
