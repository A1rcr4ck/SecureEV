
import threading

from dashboard3 import app, sim_loop, REAL


def main():
    mode = "real modules" if REAL else "mock simulation"

    print(f"\nSecureEV Network Dashboard v3 — {mode}")
    print("Open: http://localhost:5002\n")

    simulation_thread = threading.Thread(
        target=sim_loop,
        daemon=True
    )
    simulation_thread.start()

    app.run(
        host="127.0.0.1",
        port=5002,
        debug=False,
        threaded=True
    )


if __name__ == "__main__":
    main()
