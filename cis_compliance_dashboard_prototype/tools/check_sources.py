"""Verify local source pins offline. Does not attest human approval or VM readiness."""
from pathlib import Path
from backends.ubuntu.catalogue import load_catalogue


if __name__ == '__main__':
    root = Path(__file__).resolve().parents[1] / 'catalogues'
    catalogue = load_catalogue(root / 'ubuntu2204.json', root / 'source-lock.json')
    print(f'{len(catalogue.controls)} controls; source hashes and actual SCAP mappings verified.')
    print(f'Activation ready: {catalogue.activation_ready}. This check is not live validation or human review.')
