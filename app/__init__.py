import os
from flask import Flask
from .models import init_db


def create_app():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    app = Flask(__name__,
                template_folder=os.path.join(root, 'templates'),
                static_folder=os.path.join(root, 'static'))
    app.config['SECRET_KEY'] = 'ssrf-lab-neon-x'
    init_db()
    from .routes import bp
    app.register_blueprint(bp)
    return app


def create_internal_app():
    app = Flask('ssrf-internal')
    from .internal import bp as internal_bp
    app.register_blueprint(internal_bp)
    return app