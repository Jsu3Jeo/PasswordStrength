from flask import Flask, render_template, request, jsonify
from estimator import analyze_password

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index(): 
    return render_template("index.html")

@app.post("/api/analyze")
def api_analyze():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
 
    result = analyze_password(password)

    return jsonify({
        "length": result.length,
        "charset_size": result.charset_size,
        "entropy_bits": result.entropy_bits,
        "score": result.score,
        "verdict": result.verdict,
        "warnings": result.warnings,
        "suggestions": result.suggestions,
        "crack_times": result.crack_times, 
    })

if __name__ == "__main__":
    app.run(debug=True)
