from __future__ import annotations
from typing import Optional, Any
import json

class DrawData():
    image_size: tuple[float, float] = (60, 40)

    lines: list[Line]
    images: list[BracketImage]

    def __init__(self, json: Optional[str]=None) -> None:
        if json:
            self.from_json(json)
        else:
            self.lines = []
            self.images = []
    
    def add_lines(self, lines: list[Line]):
        self.lines += lines

    def to_json(self) -> str:
        return json.dumps(
            self,
            default=lambda o: o.__dict__, 
            sort_keys=True)
    
    def from_json(self, json_str: str) -> None:
        json_obj = json.loads(json_str)
        self.image_size = (json_obj['image_size'][0],json_obj['image_size'][1])
        self.lines = [Line(l['x'], l['y'], l['size'], l['isVert']) for l in json_obj['lines']]
        self.images = [BracketImage(img['x'], img['y']) for img in json_obj['images']]


class Line():
    x: float
    y: float
    size: float
    isVert: bool

    def __init__(self, x: float, y: float, size: float, isVert: bool) -> None:
        self.x = x
        self.y = y
        self.size = size
        self.isVert = isVert


class BracketImage():
    x: float
    y: float
    index: str

    def __init__(self, x: float, y: float):
        self.x = x
        self.y = y