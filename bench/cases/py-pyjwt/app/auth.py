import jwt


def issue(user_id, secret):
    return jwt.encode({"sub": user_id}, secret, algorithm="HS256").decode("utf-8")


def user_from(token, secret):
    return jwt.decode(token, secret)["sub"]
