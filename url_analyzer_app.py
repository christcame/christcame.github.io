import requests
from bs4 import BeautifulSoup
from flask import Flask, request, render_template
from textblob import TextBlob

app = Flask(__name__)

def analyze_text(text: str) -> dict:
    blob = TextBlob(text)
    polarity = blob.sentiment.polarity
    subjectivity = blob.sentiment.subjectivity

    if polarity > 0.1:
        tone = "positive"
    elif polarity < -0.1:
        tone = "negative"
    else:
        tone = "neutral"

    if subjectivity > 0.5:
        emotion = "subjective or emotional"
    else:
        emotion = "objective or neutral"

    lower_text = text.lower()
    if "not intended" in lower_text or "no guarantee" in lower_text:
        subtext = "Possible disclaimer or hidden warning"
    else:
        subtext = "No obvious subtext"

    return {
        "polarity": round(polarity, 3),
        "subjectivity": round(subjectivity, 3),
        "tone": tone,
        "emotion": emotion,
        "subtext": subtext,
    }

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        url = request.form.get("url", "")
        try:
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")
            text = soup.get_text(separator=" ", strip=True)
            result = analyze_text(text[:5000])
            result["url"] = url
        except Exception as e:
            result = {"error": str(e), "url": url}
    return render_template("url_analyzer.html", result=result)

if __name__ == "__main__":
    app.run(port=5010, debug=True)
