from cipher_breaker import caesar, crack_caesar, crack_vigenere, vigenere

PLAIN = (
    "It was a bright cold day in April and the clocks were striking thirteen. "
    "Winston Smith his chin nuzzled into his breast in an effort to escape the vile wind "
    "slipped quickly through the glass doors of Victory Mansions though not quickly enough "
    "to prevent a swirl of gritty dust from entering along with him. The hallway smelt of "
    "boiled cabbage and old rag mats. At one end of it a coloured poster too large for "
    "indoor display had been tacked to the wall."
)


def test_caesar_round_trip_preserves_case_and_symbols():
    assert caesar(caesar("Hello, World!", 7), -7) == "Hello, World!"


def test_crack_caesar():
    shift, plain = crack_caesar(caesar(PLAIN, 11))
    assert shift == 11 and plain == PLAIN


def test_vigenere_known_vector():
    assert vigenere("ATTACKATDAWN", "LEMON") == "LXFOPVEFRNHR"
    assert vigenere("LXFOPVEFRNHR", "LEMON", decrypt=True) == "ATTACKATDAWN"


def test_crack_vigenere_recovers_key():
    key, plain = crack_vigenere(vigenere(PLAIN, "ORWELL"))
    assert key == "ORWELL"
    assert plain == PLAIN
