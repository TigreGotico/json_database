class InvalidItemID(ValueError):
    """ ItemID is invalid """


class DatabaseNotCommitted(FileNotFoundError):
    """ Database has not been saved in yet """


class SessionError(RuntimeError):
    """ Could not commit database"""


class MatchError(ValueError):
    """ could not match an item in db """


class DecryptionKeyError(KeyError):
    """ Could not decrypt payload """


class EncryptionKeyError(KeyError):
    """ Could not encrypt payload """
