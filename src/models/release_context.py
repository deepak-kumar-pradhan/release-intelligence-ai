class ReleaseContext:
    def __init__(self, release_manifest=None, session_data=None):
        if release_manifest is not None and not isinstance(release_manifest, dict):
            raise TypeError("release_manifest must be a dict")
        if session_data is not None and not isinstance(session_data, dict):
            raise TypeError("session_data must be a dict")

        self.release_manifest = dict(release_manifest or {})
        self.session_data = dict(session_data or {})

    def update_release_manifest(self, new_manifest):
        if not isinstance(new_manifest, dict):
            raise TypeError("new_manifest must be a dict")
        self.release_manifest.update(new_manifest)

    def get_release_manifest(self):
        return dict(self.release_manifest)

    def update_session_data(self, key, value):
        if not isinstance(key, str) or not key.strip():
            raise ValueError("session key must be a non-empty string")
        self.session_data[key] = value

    def get_session_data(self, key):
        if not isinstance(key, str) or not key.strip():
            return None
        return self.session_data.get(key, None)

    def clear_session_data(self):
        self.session_data.clear()