from werkzeug.urls import url_quote


def file_link(path):
    return "/files/" + url_quote(path)
