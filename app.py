from flask import Flask, render_template, request
from scanner import crawl_and_scan  # your updated scanner functions
from colorama import Fore, Style

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    if request.method == "POST":
        target_url = request.form.get("target")
        if target_url:
            visited = set()
            MAX_PAGES = 20
            pages_scanned = [0]  # mutable counter

            # Redirect scanner output to results list
            import sys
            import io
            old_stdout = sys.stdout
            sys.stdout = mystdout = io.StringIO()

            crawl_and_scan(target_url, visited, MAX_PAGES, pages_scanned)

            sys.stdout = old_stdout
            results = mystdout.getvalue().splitlines()

    return render_template("index.html", results=results)
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
