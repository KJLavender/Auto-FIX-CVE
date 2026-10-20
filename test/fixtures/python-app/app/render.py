import yaml
import requests
from jinja2 import Template


def load_config(text):
    return yaml.load(text, Loader=yaml.FullLoader)


def render(template_source, **context):
    return Template(template_source).render(**context)


def fetch(url):
    return requests.get(url, timeout=5).text
