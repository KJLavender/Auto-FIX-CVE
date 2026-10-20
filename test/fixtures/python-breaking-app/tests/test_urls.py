from app.urls import file_link


def test_file_link_escapes_spaces():
    assert file_link("my report.pdf") == "/files/my%20report.pdf"
