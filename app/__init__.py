from flask import Flask

def create_app():
    app = Flask(__name__)
    app.secret_key = 's3cR3tK3y!@#12345678_abcdef'

    with app.app_context():
        from .routes import main_routes
        app.register_blueprint(main_routes)

    return app