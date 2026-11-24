"""Web interface for the recorded reconnaissance report."""

from flask import Flask, jsonify, render_template

from src.recon import build_report


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    app.config.from_mapping(JSON_SORT_KEYS=False)
    if test_config:
        app.config.update(test_config)
    report = build_report()

    @app.get("/")
    def home():
        return render_template("index.html", report=report)

    @app.get("/api/report")
    def api_report():
        return jsonify(report)

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "mode": "recorded-metadata-report"})

    return app


app = create_app()
