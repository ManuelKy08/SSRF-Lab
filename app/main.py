import threading
import webbrowser

PORT = 5092
INTERNAL_PORT = 5091


def main():
    from app import create_app, create_internal_app
    from app.models import seed

    seed()

    internal = create_internal_app()
    t = threading.Thread(target=internal.run,
                         kwargs={'host': '127.0.0.1', 'port': INTERNAL_PORT,
                                 'debug': False, 'use_reloader': False},
                         daemon=True)
    t.start()

    threading.Timer(1.2, lambda: webbrowser.open(f'http://127.0.0.1:{PORT}/')).start()
    create_app().run(host='127.0.0.1', port=PORT, debug=False, use_reloader=False)


if __name__ == '__main__':
    main()