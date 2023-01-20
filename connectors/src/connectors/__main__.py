from connectors.app import app
from waitress import serve

if __name__ == "__main__":
    # Deployment on Weitress
    serve(app, host='0.0.0.0', port=5000)
    # Should be it changed to 192.168.0.1
