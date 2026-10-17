# Bu dosyanın varlığı pytest'in proje kökünü sys.path'e eklemesini sağlar,
# böylece `pytest` (konsol scripti) ile de `import app` çalışır — CI'da
# `pytest -q` komutu "ModuleNotFoundError: app" vermez.
