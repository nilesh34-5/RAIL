"""Writes config/speed_noml.yaml: a copy of config/rail.yaml with the three
ML detectors switched off. Used for the "RAIL with inspection off" speed test.
config/rail.yaml itself is not changed.

Run on the sender from ~/RAIL1:   python3 wired_test/make_noml_config.py
"""
import yaml

ML = ("ember2024_ml", "malconv_ml", "malconvgct_ml")

with open("config/rail.yaml", encoding="utf-8") as fh:
    cfg = yaml.safe_load(fh)
for name in ML:
    cfg["inspection"]["detectors"][name]["enabled"] = False
with open("config/speed_noml.yaml", "w", encoding="utf-8") as fh:
    yaml.safe_dump(cfg, fh, sort_keys=False)
print("wrote config/speed_noml.yaml (ML detectors off:", ", ".join(ML) + ")")
