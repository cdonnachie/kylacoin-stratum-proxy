import argparse
from .run import run_with_settings
from .config import Settings


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ip", default=None)
    p.add_argument("--port", type=int, default=None)
    p.add_argument("--rpcip", default=None)
    p.add_argument("--rpcport", type=int, default=None)
    p.add_argument("--rpcuser", default=None)
    p.add_argument("--rpcpass", default=None)
    p.add_argument("--aux-rpcip", default=None)
    p.add_argument("--aux-rpcport", type=int, default=None)
    p.add_argument("--aux-rpcuser", default=None)
    p.add_argument("--aux-rpcpass", default=None)
    p.add_argument("--aux-address", default=None)
    p.add_argument("--proxy-signature", default=None)
    p.add_argument("--use-easier-target", action="store_true")
    p.add_argument("-t", "--testnet", action="store_true")
    p.add_argument("-j", "--jobs", action="store_true")
    p.add_argument("-v", "--verbose", "--debug", action="store_true", dest="verbose")
    p.add_argument(
        "--log-level",
        default=None,
        help="Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
    )
    p.add_argument("--debug-shares", action="store_true")
    # ZMQ options
    p.add_argument("--enable-zmq", action="store_true", help="Enable ZMQ notifications")
    p.add_argument(
        "--disable-zmq", action="store_true", help="Disable ZMQ notifications"
    )
    p.add_argument("--kcn-zmq-endpoint", default=None, help="KCN ZMQ endpoint")
    p.add_argument("--lcn-zmq-endpoint", default=None, help="LCN ZMQ endpoint")
    args = p.parse_args()

    s = Settings()
    for k, v in vars(args).items():
        if v is not None:
            # Handle ZMQ enable/disable logic
            if k == "enable_zmq" and v:
                setattr(s, "enable_zmq", True)
            elif k == "disable_zmq" and v:
                setattr(s, "enable_zmq", False)
            else:
                setattr(s, k.replace("-", "_"), v)

    if not s.rpcuser or not s.rpcpass:
        raise SystemExit(
            "KCN RPC credentials are required (--rpcuser/--rpcpass or env vars)."
        )
    run_with_settings(s)


if __name__ == "__main__":
    main()
