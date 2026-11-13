"""Is the local AI ready for a round? (Module 2, Ubuntu page; run only when the administrator clicks Check AI.)

A tiny timed request to qwen3:8b (which also loads the model and keeps it loaded for Ollama's keep-alive), the
laptop's free memory, and whether Ollama holds the model on the GPU or partly on the CPU (`/api/ps`, the data `ollama
ps` shows). Everything stays on this laptop: loopback only, nothing about any server is sent. The protected
`hardening/ollama_client.py` is used as it is.

Live 11 November 13:42: about 1.8 GB of 16 GB free, and two agent requests timed out after the scan.
"""
from dataclasses import dataclass
import http.client
import json
import time

SLOW_SECONDS = 20      # A warm qwen3:8b answers a one-word request in a second or two.
DOWN_SECONDS = 60      # The tiny request's own time limit.
MIN_FREE_GB = 2.0
PROMPT = [{'role': 'user', 'content': 'Reply with the single word OK.'}]


@dataclass(frozen=True)
class Readiness:
    state: str             # 'ready', 'slow' or 'down'
    seconds: float | None  # the tiny request's response time
    free_gb: float | None  # free laptop memory, or None when it could not be read
    processor: str         # '100% GPU', '45% CPU / 55% GPU', '100% CPU', 'not loaded' or 'unknown'
    reasons: tuple
    text: str


def _chat():
    from hardening.ollama_client import OllamaClient
    OllamaClient(num_predict=64).chat(PROMPT, [], timeout=DOWN_SECONDS)


def _available():
    from hardening.ollama_client import model_available
    return model_available(timeout=2.0)


def _processes():
    connection = http.client.HTTPConnection('127.0.0.1', 11434, timeout=2.0)
    try:
        connection.request('GET', '/api/ps')
        response = connection.getresponse()
        if response.status != 200:
            raise OSError('Ollama /api/ps status %d' % response.status)
        return json.loads(response.read(1048576))
    finally:
        connection.close()


def _free_memory():
    """Free physical memory in GB, or None."""
    try:
        import ctypes

        class Status(ctypes.Structure):
            _fields_ = [('length', ctypes.c_ulong), ('load', ctypes.c_ulong), ('total', ctypes.c_ulonglong),
                        ('available', ctypes.c_ulonglong), ('total_page', ctypes.c_ulonglong),
                        ('available_page', ctypes.c_ulonglong), ('total_virtual', ctypes.c_ulonglong),
                        ('available_virtual', ctypes.c_ulonglong), ('available_extended', ctypes.c_ulonglong)]
        status = Status()
        status.length = ctypes.sizeof(Status)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return round(status.available / 1024 ** 3, 1)
    except (AttributeError, OSError):
        pass
    try:
        with open('/proc/meminfo', encoding='ascii') as info:
            for line in info:
                if line.startswith('MemAvailable:'):
                    return round(int(line.split()[1]) / 1024 ** 2, 1)
    except (OSError, ValueError):
        pass
    return None


def _processor(processes, model):
    try:
        entry = next((m for m in processes().get('models', ()) if m.get('name') == model), None)
    except (OSError, ValueError, AttributeError, TypeError):
        return 'unknown', None
    if entry is None:
        return 'not loaded', None
    size, vram = entry.get('size'), entry.get('size_vram')
    if type(size) is not int or type(vram) is not int or size <= 0:
        return 'unknown', None
    gpu = round(100 * vram / size)
    text = '100% GPU' if gpu >= 100 else '100% CPU' if gpu <= 0 else f'{100 - gpu}% CPU / {gpu}% GPU'
    return text, gpu


def check(*, chat=_chat, available=_available, processes=_processes, free_memory=_free_memory, clock=time.monotonic):
    from hardening.ollama_client import OllamaClient
    model = OllamaClient.model
    free = free_memory()
    if not available():
        return Readiness('down', None, free, 'unknown', ('the model is not available',),
                         f'AI not answering: Ollama is not running or {model} is not pulled. Start Ollama with '
                         f'{model}, then click Check AI again.')
    started = clock()
    try:
        chat()
        failure = None
    except Exception as error:  # timeout, refused connection, bad answer: the AI did not answer
        failure = type(error).__name__
    seconds = round(clock() - started, 1)
    if failure is None and seconds > DOWN_SECONDS:
        failure = f'over {DOWN_SECONDS} s'
    processor, gpu = _processor(processes, model)
    if failure:
        return Readiness('down', seconds, free, processor, ('no answer: ' + failure,),
                         f'AI not answering: a one-word request to {model} got no answer ({failure}). Start Ollama '
                         f'with {model}, free memory, then click Check AI again. A round cannot start meanwhile.')
    reasons = []
    if seconds > SLOW_SECONDS:
        reasons.append(f'answered in {seconds:g} s (over {SLOW_SECONDS} s)')
    if free is not None and free < MIN_FREE_GB:
        reasons.append(f'only {free:g} GB of laptop memory free (under {MIN_FREE_GB:g} GB)')
    if gpu is not None and gpu < 100:
        reasons.append(f'the model runs partly on the CPU ({processor})')
    facts = f'answered in {seconds:g} s · model on {processor} · ' + (f'{free:g} GB free' if free is not None
                                                                      else 'free memory unknown')
    if reasons:
        return Readiness('slow', seconds, free, processor, tuple(reasons),
                         'AI slow: ' + '; '.join(reasons) + '. Close other programs (or pause the server VM if it is '
                         'not needed yet) to free memory, or the agents may time out during the round.')
    return Readiness('ready', seconds, free, processor, (), 'AI ready: ' + facts + '.')
