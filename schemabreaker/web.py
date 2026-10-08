"""SchemaBreaker Web Server launcher."""

import os
import sys
import uvicorn


def launch_web_server(host: str = "127.0.0.1", port: int = 8501, reload: bool = False):
    """Starts the FastAPI web server."""
    print(f"\n⚡ Starting SchemaBreaker Web Application on http://{host}:{port}\n")
    uvicorn.run("web.app:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8501))
    host = os.environ.get("HOST", "127.0.0.1")
    launch_web_server(host=host, port=port)
