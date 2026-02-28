class ReleaseContext:
    def __init__(self, release_manifest=None, session_data=None):
        self.release_manifest = release_manifest if release_manifest is not None else {}
        self.session_data = session_data if session_data is not None else {}

    def update_release_manifest(self, new_manifest):
        self.release_manifest.update(new_manifest)

    def get_release_manifest(self):
        return self.release_manifest

    def update_session_data(self, key, value):
        self.session_data[key] = value

    def get_session_data(self, key):
        return self.session_data.get(key, None)

    def clear_session_data(self):
        self.session_data.clear()