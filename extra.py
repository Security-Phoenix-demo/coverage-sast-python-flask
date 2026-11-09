# Deliberately vulnerable test code (medium / low rated issues). Do not deploy.
import traceback

from flask import Blueprint, make_response, redirect, request

extra = Blueprint("extra", __name__)


@extra.route("/boom")
def boom():
    # Stack trace exposure
    try:
        return str(1 / int(request.args["n"]))
    except Exception:
        return traceback.format_exc(), 500


@extra.route("/session")
def session_cookie():
    # Cookie without Secure / HttpOnly, value from the request
    resp = make_response("set")
    resp.set_cookie("session", request.args["id"], secure=False, httponly=False)
    return resp


@extra.route("/back")
def back():
    # Open redirect
    return redirect(request.args.get("return_to", "/"))
