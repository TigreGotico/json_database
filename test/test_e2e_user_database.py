"""
End-to-end tests using a realistic user database scenario.

Demonstrates typical usage patterns: create a user database, add/remove/search users,
apply filters, and persist across sessions.
"""

import pytest
import tempfile
import os
from json_database import JsonDatabase
from json_database.search import Query


@pytest.fixture
def user_db_path():
    """Temporary path for test database."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield os.path.join(tmpdir, "users.jsondb")


class TestUserDatabaseE2E:
    """End-to-end tests with a realistic user database."""

    def test_create_and_populate_user_database(self, user_db_path):
        """Create a user database and add sample users."""
        db = JsonDatabase("users", path=user_db_path, disable_lock=True)

        users = [
            {"id": 1, "name": "Alice Chen", "email": "alice@example.com", "role": "admin", "active": True, "score": 95},
            {"id": 2, "name": "Bob Smith", "email": "bob@example.com", "role": "user", "active": True, "score": 72},
            {"id": 3, "name": "Carol Davis", "email": "carol@example.com", "role": "moderator", "active": False, "score": 88},
            {"id": 4, "name": "David Wilson", "email": "dave@example.com", "role": "user", "active": True, "score": 65},
            {"id": 5, "name": "Eve Martinez", "email": "eve@example.com", "role": "admin", "active": True, "score": 91},
        ]

        for user in users:
            db.add_item(user)

        assert len(db) == 5
        db.commit()

    def test_query_users_by_role(self, user_db_path):
        """Query users by role using the Query builder."""
        db = JsonDatabase("users", path=user_db_path, disable_lock=True)

        users = [
            {"id": 1, "name": "Alice", "role": "admin", "active": True},
            {"id": 2, "name": "Bob", "role": "user", "active": True},
            {"id": 3, "name": "Carol", "role": "admin", "active": False},
            {"id": 4, "name": "David", "role": "user", "active": True},
        ]
        for user in users:
            db.add_item(user)

        # Find all admins
        admins = Query(db).equal("role", "admin").build()
        assert len(admins) == 2
        assert all(u["role"] == "admin" for u in admins)

        # Find all active users
        active = Query(db).equal("active", True).build()
        assert len(active) == 3

        # Find active admins
        active_admins = Query(db).equal("role", "admin").equal("active", True).build()
        assert len(active_admins) == 1
        assert active_admins[0]["name"] == "Alice"

    def test_filter_users_by_score_range(self, user_db_path):
        """Filter users by score range using comparison operators."""
        db = JsonDatabase("users", path=user_db_path, disable_lock=True)

        users = [
            {"id": 1, "name": "Alice", "score": 95},
            {"id": 2, "name": "Bob", "score": 72},
            {"id": 3, "name": "Carol", "score": 88},
            {"id": 4, "name": "David", "score": 65},
            {"id": 5, "name": "Eve", "score": 91},
        ]
        for user in users:
            db.add_item(user)

        # High performers (score >= 85)
        high_performers = Query(db).above_or_equal("score", 85).build()
        assert len(high_performers) == 3
        assert all(u["score"] >= 85 for u in high_performers)

        # Low performers (score < 75)
        low_performers = Query(db).below("score", 75).build()
        assert len(low_performers) == 2
        assert all(u["score"] < 75 for u in low_performers)

        # Score in range [70, 90)
        mid_range = Query(db).above_or_equal("score", 70).below("score", 90).build()
        assert len(mid_range) == 2

    def test_search_users_by_name(self, user_db_path):
        """Search for users by name using fuzzy matching."""
        db = JsonDatabase("users", path=user_db_path, disable_lock=True)

        users = [
            {"id": 1, "name": "Alice Chen"},
            {"id": 2, "name": "Bob Smith"},
            {"id": 3, "name": "Carol Davis"},
            {"id": 4, "name": "David Wilson"},
        ]
        for user in users:
            db.add_item(user)

        # Exact name search
        results = Query(db).equal("name", "Bob Smith").build()
        assert len(results) == 1
        assert results[0]["id"] == 2

        # Fuzzy name search (token-based)
        results = Query(db).value_contains_token("name", "Chen").build()
        assert len(results) == 1
        assert results[0]["name"] == "Alice Chen"

        # Value contains (substring)
        results = Query(db).value_contains("name", "David").build()
        assert len(results) == 1
        assert results[0]["id"] == 4

    def test_remove_and_reactivate_user(self, user_db_path):
        """Test removing and conditionally reactivating a user."""
        db = JsonDatabase("users", path=user_db_path, disable_lock=True)

        users = [
            {"id": 1, "name": "Alice", "status": "active"},
            {"id": 2, "name": "Bob", "status": "active"},
            {"id": 3, "name": "Carol", "status": "active"},
        ]
        for user in users:
            db.add_item(user)

        assert len(db) == 3

        # Remove a user (tombstone)
        db.remove_item(1)
        assert len(db) == 2

        # The slot is still there but inaccessible
        with pytest.raises(Exception):  # InvalidItemID
            db[1]

        # Remaining users are intact
        results = Query(db).equal("status", "active").build()
        assert len(results) == 2
        assert all(u["name"] in ["Alice", "Carol"] for u in results)

        db.commit()

    def test_update_user_profile(self, user_db_path):
        """Test updating a user's profile information."""
        db = JsonDatabase("users", path=user_db_path, disable_lock=True)

        user = {"id": 1, "name": "Alice", "email": "alice@old.com", "score": 50}
        db.add_item(user)

        # Get the user's ID
        user_id = db.get_item_id(user)
        assert user_id == 0

        # Update via direct assignment
        updated_user = {"id": 1, "name": "Alice", "email": "alice@new.com", "score": 95}
        db[user_id] = updated_user

        # Verify update
        retrieved = db[user_id]
        assert retrieved["email"] == "alice@new.com"
        assert retrieved["score"] == 95

    def test_persistence_across_sessions(self, user_db_path):
        """Test that database persists across session boundaries."""
        # Session 1: Create and populate
        db1 = JsonDatabase("users", path=user_db_path, disable_lock=True)
        users = [
            {"id": 1, "name": "Alice"},
            {"id": 2, "name": "Bob"},
            {"id": 3, "name": "Carol"},
        ]
        for user in users:
            db1.add_item(user)
        db1.commit()
        assert len(db1) == 3

        # Session 2: Reload and verify
        db2 = JsonDatabase("users", path=user_db_path, disable_lock=True)
        assert len(db2) == 3

        # Query in new session
        results = Query(db2).equal("name", "Bob").build()
        assert len(results) == 1

        # Add more users
        db2.add_item({"id": 4, "name": "David"})
        assert len(db2) == 4
        db2.commit()

        # Session 3: Verify persistence
        db3 = JsonDatabase("users", path=user_db_path, disable_lock=True)
        assert len(db3) == 4
        assert any(u["name"] == "David" for u in db3)

    def test_complex_user_query_chain(self, user_db_path):
        """Test complex query chains with multiple filters."""
        db = JsonDatabase("users", path=user_db_path, disable_lock=True)

        users = [
            {"id": 1, "name": "Alice", "dept": "engineering", "salary": 120000, "level": "senior", "active": True},
            {"id": 2, "name": "Bob", "dept": "sales", "salary": 80000, "level": "junior", "active": True},
            {"id": 3, "name": "Carol", "dept": "engineering", "salary": 110000, "level": "senior", "active": False},
            {"id": 4, "name": "David", "dept": "engineering", "salary": 95000, "level": "mid", "active": True},
            {"id": 5, "name": "Eve", "dept": "hr", "salary": 90000, "level": "mid", "active": True},
        ]
        for user in users:
            db.add_item(user)

        # Senior engineers making >= $100k who are active
        results = Query(db)\
            .equal("dept", "engineering")\
            .equal("level", "senior")\
            .above_or_equal("salary", 100000)\
            .equal("active", True)\
            .build()

        assert len(results) == 1
        assert results[0]["name"] == "Alice"

        # All active employees in engineering or hr
        engineering_or_hr = Query(db).equal("active", True).build()
        results = [u for u in engineering_or_hr if u["dept"] in ["engineering", "hr"]]
        assert len(results) == 3

    def test_bulk_operations_performance(self, user_db_path):
        """Test bulk operations with allow_duplicates flag."""
        db = JsonDatabase("users", path=user_db_path, disable_lock=True)

        # Bulk insert with allow_duplicates=True to skip duplicate checking
        for i in range(100):
            db.add_item({
                "id": i,
                "name": f"User_{i}",
                "email": f"user{i}@example.com"
            }, allow_duplicates=True)

        assert len(db) == 100

        # Query on bulk data (exact match)
        results = Query(db).equal("name", "User_5").build()
        assert len(results) == 1
        assert results[0]["id"] == 5

        db.commit()

    def test_tombstone_visibility(self, user_db_path):
        """Verify that removed items (tombstones) are invisible to queries."""
        db = JsonDatabase("users", path=user_db_path, disable_lock=True)

        users = [
            {"id": 1, "name": "Alice", "role": "admin"},
            {"id": 2, "name": "Bob", "role": "user"},
            {"id": 3, "name": "Carol", "role": "user"},
        ]
        for user in users:
            db.add_item(user)

        # Remove middle item
        db.remove_item(1)

        # Query should not see the removed item
        all_users = Query(db).all().build()
        assert len(all_users) == 2
        assert all(u["name"] in ["Alice", "Carol"] for u in all_users)

        # Length reflects only active items
        assert len(db) == 2

        # Search results exclude tombstone
        results = Query(db).equal("role", "user").build()
        assert len(results) == 1
        assert results[0]["name"] == "Carol"
