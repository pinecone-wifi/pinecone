from typing import Union, Any, Dict

from jinja2 import Template
from pathlib2 import Path


def to_args_str(args: Dict[str, Any]) -> str:
    args_lst = []

    for arg, value in args.items():
        if type(value) == bool:
            if value:
                args_lst.append("--{}".format(arg))
        else:
            args_lst.append('--{} "{}"'.format(arg, value))

    return " ".join(args_lst)


def render_template(template_path: Union[Path, str], rendered_path: Union[Path, str], render_args: Any) -> None:
    template_path = Path(template_path)
    rendered_path = Path(rendered_path)

    try:
        render_args = vars(render_args)
    except:
        pass

    template = Template(template_path.read_text())
    rendered_path.parent.mkdir(parents=True, exist_ok=True)
    rendered_path.write_text(template.render(render_args))
