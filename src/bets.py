from __future__ import annotations
from bracket import Bracket, Match, Competitor
import json

class Bets:
    '''
    A class which contains many individual Bet objects
    '''
    bets: list[Bets]

    # this function is currently storing json strings as values in json objects
    # is this bad? yeah. but its functional! and it makes more sense to store strings anyways cause we are already
    # converting implicitly from json string to Bet object so just saves us one loads/dumps call on both encode 
    # and decode. basically, if its stupid but it works, it aint stupid.
    def to_json(self) -> str:
        lst = []

        for bet in self.bets:
            json_str = bet.to_json()
            obj = { "type": type(bet).__name__, "data": json_str }
            lst += [obj]
        
        return json.dumps({'bets': lst})
    
    def from_json(self, json_string: str) -> None:
        self.bets = []
        lst = json.loads(json_string)['bets']

        for obj in lst:
            # there *has* to be a better was of doing this;.
            match obj['type']:
                case 'Moneyline':
                    bet = Moneyline()
                case _: # uh oh! someone forgot 
                    raise ValueError('type not recognized')
            
            bet.from_json(obj['data'])
            self.bets += [bet]

        

class Bet:
    '''
    A Generic Bet Class.

    parameters:
        risk: int - amount of money the user has staked on this bet.
        reward: int - the amount of money the user stands to gain if the bet pays out.
        resolved: bool - flag which is true if the bet has either payed out or busted.
    '''
    risk: int
    reward: int
    resolved: bool

    def __init__(self, risk: int = 0, reward: int = 0) -> None:
        self.risk = risk
        self.reward = reward
        self.resolved = False

    def check_if_won(self, bracket: Bracket) -> bool:
        raise NotImplementedError(f"win check not implemented for bet type {type(self)}")

    def to_json(self) -> str:
        raise NotImplementedError(f"to_json not implemented for bet type {type(self)}")

    def from_json(self, json_string: str) -> None:
        raise NotImplementedError(f"from_json not implemented for bet type {type(self)}")


class Moneyline(Bet):
    '''
    A class representing a moneyline bet.

    parameters:
        inherited:
            risk: int - amount of money the user has staked on this bet.
            reward: int - the amount of money the user stands to gain if the bet pays out.
            resolved: bool - flag which is true if the bet has either payed out or busted.
        innate:
            match_index: int - the index of the match the bet concerns
            desired_winner: Competitor - the competitor for which the bet pays out if they win 
    '''
    risk: int
    reward: int
    resolved: bool
    match_index: int
    desired_winner: Competitor

    def __init__(self, risk: int=0, reward: int=0, match_index: int=0, desired_winner: Competitor=None):
        super().__init__(risk, reward)
        self.match_index = match_index
        self.desired_winner = desired_winner

    def check_if_won(self, bracket: Bracket) -> bool:
        # if bet has been resolved, we can just halt execution
        if self.resolved:
            return False

        matches = bracket.top.generate_match_list()

        # is the betting data fucked? perchance
        if self.match_index >= len(matches):
            raise ValueError('bracket size less than match index')

        match_obj = matches[self.match_index]

        if match_obj.is_ready():
            return False

        if not match_obj.competitor:
            raise ValueError('match at match index does not have correct competitor setup')

        self.resolved = True
        return match_obj.competitor == self.desired_winner

    def to_json(self) -> str:
        obj = {
            "risk": self.risk,
            "reward": self.reward,
            "resolved": self.resolved,
            "match_index": self.match_index,
            "desired_winner": {
                "name": self.desired_winner.name,
                "deck_id": self.desired_winner.deck_id,
                "user_id": self.desired_winner.user_id,
                "defeated": self.desired_winner.defeated
            }
        }

        return json.dumps(obj)

    def from_json(self, json_string: str) -> None:
        obj = json.loads(json_string)

        self.risk = obj['risk']
        self.reward = obj['reward']
        self.resolved = obj['resolved']
        self.match_index = obj['match_index']

        d_winner = obj['desired_winner']
        comp = Competitor()
        comp.name =  d_winner['name']
        comp.deck_id = d_winner['deck_id']
        comp.user_id = d_winner['user_id']
        comp.defeated = d_winner['defeated']
        self.desired_winner = comp

# region Testing

# i'll write actual tests with like assert statements and shiz l8r.
def test():
    c1 = Competitor()
    c1.name = "steven"
    c1.user_id = 8675309
    c1.deck_id = 42
    c1.defeated = False
    b1 = Moneyline(2, 5, 12, c1)
    print(f"\n\nconverting moneyline to json: { str(b1.to_json()) }")

    b1a = Moneyline()
    b1a.from_json(b1.to_json())
    print(f"converting moneyline from json: { b1a.to_json() }")
    print(f"match? { b1a.to_json() == b1.to_json() }")

    c2 = Competitor()
    c2.name = "albert"
    c2.user_id = 8005882300
    c2.deck_id = 80085
    c2.defeated = False
    b2 = Moneyline(3, 4, 17, c2)

    bets = Bets()
    bets.bets = [b1, b2]
    print(f'\n\nconverting bets to json:\n{bets.to_json()}\n')

    bets2 = Bets()
    bets2.from_json(bets.to_json())
    print(f'converting bets from json:\n{bets2.to_json()}\n')
    print(f'match? {bets.to_json() == bets2.to_json()}')



if __name__ == "__main__":
    test()

# endregion
