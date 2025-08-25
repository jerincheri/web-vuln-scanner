from flask import Flask, render_template, request
from scanner import crawl_and_scan  # import your function

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = ""
    if request.method == "POST":
        target = request.form.get("target_url")
        if target:
            # redirect output from crawl_and_scan to a string
            import io, sys
            old_stdout = sys.stdout
            sys.stdout = mystdout = io.StringIO()
            
            crawl_and_scan(target)
            
            sys.stdout = old_stdout
            result = mystdout.getvalue()
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
