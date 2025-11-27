import json
from pathlib import Path


class StateManager:
    def __init__(self, state_file=None):
        if state_file is None:
            state_dir = Path.home() / '.NetworkThreatAnalyzer'
            state_dir.mkdir(exist_ok=True)
            state_file = state_dir / 'state.json'
        self.state_file = Path(state_file)
        self._state = self._load_state()

    # Load file from state
    def _load_state(self):
        if not self.state_file.exists():
            return {
                'last_scan_results': None,
                'scan_history': [],
                'application_settings': {}
            }
        try:
            with open(self.state_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {
                'last_scan_results': None,
                'scan_history': [],
                'application_settings': {}
            }

    # save state to file
    def _save_state(self):
        try:
            with open(self.state_file, 'w') as f:
                json.dump(self._state, f, indent=2, default=str)
            return True
        except IOError:
            return False

    # set the last scan result
    def set_last_scan_result(self, results):
        self._state['last_scan_results'] = results
        self._save_state()

    # get last scan results
    def get_last_scan_result(self):
        return self._state.get('last_scan_results')

    # add to scan to history
    def add_scan_results_to_history(self, scan_data):
        history = self._state.get('scan_history', [])

        if len(history) > 100:
            history = history[-99:]

        history.append(scan_data)
        self._state['scan_history'] = history
        self._save_state()

    # Get scan history
    def get_scan_history(self):
        return self._state.get('scan_history', [])

    # get specific scan by id
    def get_scan_by_id(self, scan_id):
        history = self.get_scan_history()
        for scan in history:
            if scan.get('id') == scan_id:
                return scan
        return None

    # cler history
    def clear_history(self):
        self._state['scan_history'] = []
        self._save_state()

    # set application settings
    def set_settings(self, key, val):
        if 'application_settings' not in self._state:
            self._state['application_settings'] = {}

        self._state['application_settings'][key] = val
        self._save_state()

    # get application settings
    def get_settings(self, key, val=None):
        return self._state.get('application_settings', {}).get(key, val)


# Global state manager
state_manager = StateManager()
