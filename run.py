# run.py
from project import create_app

app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080)
    # app.run(debug=True)