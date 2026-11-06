"""Bounded file reads must use small chunks.

Evidence (user-run on FYP-Ubuntu2204, 2026-11-06): one read(4 MiB + 1) of /proc/sys/kernel/hostname raised
OSError [Errno 12] Cannot allocate memory, because sysctl proc files allocate a buffer of the requested size.
"""
import io
import unittest


class SysctlLikeStream(io.RawIOBase):
    """Fails like /proc/sys files when asked for a large read; otherwise returns data then EOF."""
    def __init__(self, data):
        self.data, self.reads = data, []
    def readable(self):
        return True
    def read(self, size=-1):
        self.reads.append(size)
        if size < 0 or size > 65536:
            raise OSError(12, 'Cannot allocate memory')
        chunk, self.data = self.data[:size], self.data[size:]
        return chunk


class BoundedReadTests(unittest.TestCase):
    def test_reads_in_small_chunks_until_eof(self):
        from vm.ubuntu.collector import read_bounded
        stream = SysctlLikeStream(b'FYP-Ubuntu2204\n')
        self.assertEqual(read_bounded(stream, 4 * 1024 * 1024), b'FYP-Ubuntu2204\n')
        self.assertTrue(all(0 < size <= 65536 for size in stream.reads))

    def test_limit_is_still_enforced(self):
        from vm.ubuntu.collector import read_bounded
        with self.assertRaises(ValueError):
            read_bounded(SysctlLikeStream(b'x' * 200000), 100000)
        self.assertEqual(read_bounded(SysctlLikeStream(b'x' * 100000), 100000), b'x' * 100000)
