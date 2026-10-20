"""Unit tests for custom exception classes."""

import pytest
from json_database.exceptions import (
    InvalidItemID, DatabaseNotCommitted, SessionError, MatchError
)


class TestExceptionClasses:
    """Test custom exception classes."""

    def test_invalid_item_id_instantiation(self):
        """Test InvalidItemID exception can be instantiated."""
        exc = InvalidItemID()
        assert isinstance(exc, Exception)

    def test_invalid_item_id_with_message(self):
        """Test InvalidItemID with custom message."""
        exc = InvalidItemID("item 999 not found")
        assert str(exc) == "item 999 not found"

    def test_invalid_item_id_raised(self):
        """Test InvalidItemID can be raised and caught."""
        with pytest.raises(InvalidItemID):
            raise InvalidItemID("Invalid index")

    def test_database_not_committed_instantiation(self):
        """Test DatabaseNotCommitted exception can be instantiated."""
        exc = DatabaseNotCommitted()
        assert isinstance(exc, Exception)

    def test_database_not_committed_with_message(self):
        """Test DatabaseNotCommitted with custom message."""
        exc = DatabaseNotCommitted("data not saved to disk")
        assert str(exc) == "data not saved to disk"

    def test_database_not_committed_raised(self):
        """Test DatabaseNotCommitted can be raised and caught."""
        with pytest.raises(DatabaseNotCommitted):
            raise DatabaseNotCommitted("Reload failed: file not found")

    def test_session_error_instantiation(self):
        """Test SessionError exception can be instantiated."""
        exc = SessionError()
        assert isinstance(exc, Exception)

    def test_session_error_with_message(self):
        """Test SessionError with custom message."""
        exc = SessionError("context manager failed")
        assert str(exc) == "context manager failed"

    def test_session_error_raised(self):
        """Test SessionError can be raised and caught."""
        with pytest.raises(SessionError):
            raise SessionError("Failed to commit")

    def test_match_error_instantiation(self):
        """Test MatchError exception can be instantiated."""
        exc = MatchError()
        assert isinstance(exc, Exception)

    def test_match_error_with_message(self):
        """Test MatchError with custom message."""
        exc = MatchError("no matching item found")
        assert str(exc) == "no matching item found"

    def test_match_error_raised(self):
        """Test MatchError can be raised and caught."""
        with pytest.raises(MatchError):
            raise MatchError("Item not found in database")

    def test_all_exceptions_are_exception_subclasses(self):
        """Test that all custom exceptions inherit from Exception."""
        assert issubclass(InvalidItemID, Exception)
        assert issubclass(DatabaseNotCommitted, Exception)
        assert issubclass(SessionError, Exception)
        assert issubclass(MatchError, Exception)

    def test_exception_inheritance_chain(self):
        """Test exception instances are caught by Exception."""
        exceptions = [
            InvalidItemID(),
            DatabaseNotCommitted(),
            SessionError(),
            MatchError()
        ]

        for exc in exceptions:
            with pytest.raises(Exception):
                raise exc

    def test_exception_str_representation(self):
        """Test exception string representations."""
        exc1 = InvalidItemID("test message")
        exc2 = DatabaseNotCommitted("test message")
        exc3 = SessionError("test message")
        exc4 = MatchError("test message")

        # All should have string representation
        assert isinstance(str(exc1), str)
        assert isinstance(str(exc2), str)
        assert isinstance(str(exc3), str)
        assert isinstance(str(exc4), str)
