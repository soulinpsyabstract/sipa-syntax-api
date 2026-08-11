import http.server, os

UI_DIR = "/home/sipa/apps/sipa-syntax-ui/dist"

class UIHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=UI_DIR, **kwargs)
    
    def do_GET(self):
        if self.path.startswith("/api/"):
            self.send_response(404)
            self.end_headers()
            return
        super().do_GET()

print(f"Serving UI from {UI_DIR} on :5005")
http.server.HTTPServer(("127.0.0.1", 5005), UIHandler).serve_forever()
