from json_database.utils import fuzzy_match, match_one
from json_database import JsonDatabase


def _resolve_key(record, key, ignore_case=False):
    """Return the actual key in record that matches key.

    With ignore_case=True, scans all keys for a case-insensitive match so
    {"Name": "Alice"} is found by _resolve_key(record, "name", ignore_case=True).
    Returns None if no matching key exists.
    """
    if key in record:
        return key
    if ignore_case:
        kl = key.lower()
        for k in record:
            if isinstance(k, str) and k.lower() == kl:
                return k
    return None


def _get_value(record, key, ignore_case=False):
    """Return the value for key in record, resolving case-insensitively if needed."""
    resolved = _resolve_key(record, key, ignore_case)
    if resolved is None:
        raise KeyError(key)
    return record[resolved]


class Query:
    """Fluent filter builder for querying JsonDatabase items.

    Provides chainable filter methods for searching and filtering database
    records. Each method narrows the result set and returns self for chaining.

    Attributes:
        result (list): Current filtered results

    Example:
        from json_database.search import Query

        db = JsonDatabase("products")
        # ... add items ...

        # Chain filters
        query = Query(db)
        results = (query
                   .equal("category", "Electronics")
                   .below("price", 100)
                   .equal("in_stock", True)
                   .build())

        for item in results:
            print(item["name"])
    """
    def __init__(self, db):
        """Initialize Query from database or single item.

        Args:
            db: JsonDatabase instance or dict to filter
        """
        if isinstance(db, JsonDatabase):
            self.result = list(db)
        else:
            self.result = [db]

    def contains_key(self, key, fuzzy=False, thresh=0.7, ignore_case=False):
        if fuzzy:
            after = []
            for e in self.result:
                filter = True
                for k in e:
                    if ignore_case:
                        score = fuzzy_match(k.lower(), key.lower())
                    else:
                        score = fuzzy_match(k, key)
                    if score < thresh:
                        continue
                    filter = False
                if not filter:
                    after.append(e)
            self.result = after
        elif ignore_case:
            self.result = [a for a in self.result
                           if _resolve_key(a, key, ignore_case=True) is not None]
        else:
            self.result = [a for a in self.result if key in a]
        return self

    def contains_value(self, key, value, fuzzy=False, thresh=0.75, ignore_case=False):
        self.contains_key(key, ignore_case=ignore_case)
        if fuzzy:
            after = []
            for e in self.result:
                v = _get_value(e, key, ignore_case)
                if isinstance(v, str):
                    score = fuzzy_match(value.lower(), v.lower()) if ignore_case else fuzzy_match(value, v)
                    if score > thresh:
                        after.append(e)
                elif isinstance(v, list):
                    _, score = (match_one(value.lower(), [_.lower() for _ in v])
                                if ignore_case else match_one(value, v))
                    if score >= thresh:
                        after.append(e)
                elif isinstance(v, dict):
                    _, score = (match_one(value.lower(), [_.lower() for _ in v.keys()])
                                if ignore_case else match_one(value, v))
                    if score >= thresh:
                        after.append(e)
            self.result = after
        elif ignore_case and isinstance(value, str):
            after = []
            for a in self.result:
                v = _get_value(a, key, ignore_case)
                if isinstance(v, str) and value.lower() in v.lower():
                    after.append(a)
                elif value.lower() in v or value in v:
                    after.append(a)
            self.result = after
        else:
            self.result = [a for a in self.result if value in _get_value(a, key)]
        return self

    def value_contains(self, key, value, ignore_case=False):
        self.contains_key(key, ignore_case=ignore_case)
        if ignore_case:
            after = []
            sv = str(value).lower()
            for e in self.result:
                v = _get_value(e, key, ignore_case)
                if isinstance(v, str):
                    if sv in v.lower():
                        after.append(e)
                elif isinstance(v, list):
                    if sv in [str(_).lower() for _ in v]:
                        after.append(e)
                elif isinstance(v, dict):
                    if sv in [str(_).lower() for _ in v.keys()]:
                        after.append(e)
            self.result = after
        else:
            self.result = [e for e in self.result if value in _get_value(e, key)]
        return self

    def value_contains_token(self, key, value, fuzzy=False, thresh=0.75, ignore_case=False):
        self.contains_key(key, ignore_case=ignore_case)
        after = []
        value = str(value)
        for e in self.result:
            v = _get_value(e, key, ignore_case)
            if isinstance(v, str):
                if fuzzy:
                    _, score = match_one(value.lower(), v.lower().split(" "))
                    if score > thresh:
                        after.append(e)
                elif ignore_case and value.lower() in v.lower().split(" "):
                    after.append(e)
                elif value in v.split(" "):
                    after.append(e)
            elif value in v:
                after.append(e)
        self.result = after
        return self

    def equal(self, key, value, ignore_case=False):
        self.contains_key(key, ignore_case=ignore_case)
        if ignore_case and isinstance(value, str):
            self.result = [a for a in self.result
                           if _get_value(a, key, ignore_case).lower() == value.lower()]
        else:
            self.result = [a for a in self.result if _get_value(a, key) == value]
        return self

    def below(self, key, value, ignore_case=False):
        self.contains_key(key, ignore_case=ignore_case)
        self.result = [a for a in self.result if _get_value(a, key, ignore_case) < value]
        return self

    def above(self, key, value, ignore_case=False):
        self.contains_key(key, ignore_case=ignore_case)
        self.result = [a for a in self.result if _get_value(a, key, ignore_case) > value]
        return self

    def below_or_equal(self, key, value, ignore_case=False):
        self.contains_key(key, ignore_case=ignore_case)
        self.result = [a for a in self.result if _get_value(a, key, ignore_case) <= value]
        return self

    def above_or_equal(self, key, value, ignore_case=False):
        self.contains_key(key, ignore_case=ignore_case)
        self.result = [a for a in self.result if _get_value(a, key, ignore_case) >= value]
        return self

    def in_range(self, key, min_value, max_value, ignore_case=False):
        self.contains_key(key, ignore_case=ignore_case)
        self.result = [a for a in self.result
                       if min_value < _get_value(a, key, ignore_case) < max_value]
        return self

    def all(self):
        """No-op filter that returns all items (identity).

        Returns:
            self for chaining
        """
        return self

    def build(self):
        """Return the current filtered result list.

        Returns:
            list: Filtered items matching all applied filters
        """
        return self.result


