from __future__ import annotations
from typing import Optional, Any
import json
from pprint import pprint

class Bracket:
    name: str
    top: Match


    def __init__(self) -> None:
        self.name = ""
        self.top = Match()


    def to_json(self) -> str:
        in_matches_list = self.top.generate_match_list()
        out_matches_list = []

        matches_index_dict = {in_matches_list[i]: i for i in range(len(in_matches_list))}
        
        for match in in_matches_list:
            competitor = {"name": match.competitor.name, "owner_id": match.competitor.owner_id, "deck_id": match.competitor.deck_id} if match.competitor else -1
            out_matches_list += [{"competitor": competitor, 
                                  "left": matches_index_dict[match.left] if match.left else -1,
                                  "right": matches_index_dict[match.right]if match.right else -1}]

        data = {
            "name": self.name,
            "matches": out_matches_list,
        }

        return json.dumps(data)
    

    def from_json(self, json_string: str) -> None:
        data = json.loads(json_string)

        self.name = data["name"]
        self.top = self.build_matches_from_json_data(data["matches"])


    def build_matches_from_json_data(self, data: list[dict[str, Any]], i: int = 0) -> Match:
        m = Match()
        
        if data[i]["competitor"] == -1:
            comp = None
        else:
            comp = Competitor()
            comp.name = data[i]["competitor"]["name"]
            comp.owner_id = data[i]["competitor"]["owner_id"]
            comp.deck_id = data[i]["competitor"]["deck_id"]
            
        m.competitor = comp
        m.left = None if data[i]["left"] == -1 else self.build_matches_from_json_data(data, data[i]["left"])
        m.right = None if data[i]["right"] == -1 else self.build_matches_from_json_data(data, data[i]["right"])

        return m


class Match:
    competitor: Optional[Competitor]
    left: Optional[Match]
    right: Optional[Match]

    def __init__(self, competitor: Optional[Competitor] = None) -> None:
        self.competitor = competitor
        self.left = None
        self.right = None

    def is_ready(self) -> bool:
        return self.left.competitor and self.right.competitor
    
    def declare_winner(self, leftIsWinner: bool) -> None:
        self.competitor = self.left.competitor if leftIsWinner else self.right.competitor

    # this is icky but not enough for me to care
    def generate_match_list(self) -> list[Match]:
        return [self] + \
                (self.left.generate_match_list() if self.left else []) + \
                (self.right.generate_match_list() if self.right else [])


class Competitor:
    name: str
    owner_id: int
    deck_id: int





def test_to():
    b = Bracket()
    b.name = "test"
    b.top = Match()
    b.top.left = Match()
    b.top.left.left = Match()
    b.top.left.left.competitor = Competitor()
    b.top.left.left.competitor.name = "LL"
    b.top.left.left.competitor.owner_id = 123
    b.top.left.left.competitor.deck_id = 456
    b.top.left.right = Match()
    b.top.left.right.competitor = Competitor()
    b.top.left.right.competitor.name = "LR"
    b.top.left.right.competitor.owner_id = 147
    b.top.left.right.competitor.deck_id = 258
    b.top.right = Match()
    b.top.right.left = Match()
    b.top.right.left.competitor = Competitor()
    b.top.right.left.competitor.name = "RL"
    b.top.right.left.competitor.owner_id = 987
    b.top.right.left.competitor.deck_id = 654
    b.top.right.right = Match()
    b.top.right.right.competitor = Competitor()
    b.top.right.right.competitor.name = "RR"
    b.top.right.right.competitor.owner_id = 963
    b.top.right.right.competitor.deck_id = 852
    print(b.to_json())


def test_from():
    json_string = '{"name": "test", "matches": [{"competitor": -1, "left": 1, "right": 4}, {"competitor": -1, "left": 2, "right": 3}, {"competitor": {"name": "LL", "owner_id": 123, "deck_id": 456}, "left": -1, "right": -1}, {"competitor": {"name": "LR", "owner_id": 147, "deck_id": 258}, "left": -1, "right": -1}, {"competitor": -1, "left": 5, "right": 6}, {"competitor": {"name": "RL", "owner_id": 987, "deck_id": 654}, "left": -1, "right": -1}, {"competitor": {"name": "RR", "owner_id": 963, "deck_id": 852}, "left": -1, "right": -1}]}'
    b = Bracket()
    b.from_json(json_string)
    out = b.to_json()
    print(out)
    print(out == json_string)


if __name__ == "__main__":
    test_to()
    test_from()
