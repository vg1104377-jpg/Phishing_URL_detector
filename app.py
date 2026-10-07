from flask import Flask, render_template, request

from url_analyzer import analyze_url


app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    url = ""

    if request.method == "POST":

        url = request.form.get("url", "").strip()

        if url:
            result = analyze_url(url)

    return render_template(
        "index.html",
        result=result,
        url=url
    )


if __name__ == "__main__":
    app.run(debug=True)