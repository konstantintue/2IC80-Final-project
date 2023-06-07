from flask import Flask, render_template
import socket

app = Flask(__name__)


    
@app.route('/')
def home():
    return 'You have been spoofed, very sad 4 you :( <a href="https://www.youtube.com/watch?v=Irw9yypJOiM">click for sad catto</a>'

if __name__ == "__main__":
    app.run()
    