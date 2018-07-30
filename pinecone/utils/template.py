from typing import Union, Any

from jinja2 import Template
from pathlib2 import Path


def render_template(template_path: Union[Path, str], rendered_path: Union[Path, str], render_args: Any):
    template_path = Path(template_path)
    rendered_path = Path(rendered_path)

    try:
        render_args = vars(render_args)
    except:
        pass

    template = Template(template_path.read_text())
    rendered_path.parent.mkdir(parents=True, exist_ok=True)
    rendered_path.write_text(template.render(render_args))
