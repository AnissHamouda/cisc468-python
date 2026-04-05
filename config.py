"""
Configuration and paths for P2P Share.
"""

import os


class Config:
    def __init__(self, data_dir: str = "~/.p2p_share", port: int = 0):
        self.data_dir = os.path.expanduser(data_dir)
        self.port = port  # 0 = OS assigns

        # Sub-directories
        self.keys_dir = os.path.join(self.data_dir, "keys")
        self.shared_dir = os.path.join(self.data_dir, "shared")      # files we share
        self.received_dir = os.path.join(self.data_dir, "received")   # files we received
        self.contacts_file = os.path.join(self.data_dir, "contacts.json")
        self.share_index_file = os.path.join(self.data_dir, "share_index.json")
        self.peer_cache_file = os.path.join(self.data_dir, "peer_cache.json")
        self.state_file = os.path.join(self.data_dir, "state.json")

        self._ensure_dirs()

    def _ensure_dirs(self):
        for d in [self.data_dir, self.keys_dir, self.shared_dir, self.received_dir]:
            os.makedirs(d, mode=0o700, exist_ok=True)
