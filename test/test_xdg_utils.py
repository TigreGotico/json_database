"""Unit tests for XDG Base Directory Specification utilities."""

import os
import pytest
from pathlib import Path
from json_database.xdg_utils import (
    xdg_cache_home, xdg_config_home, xdg_data_home, xdg_state_home,
    xdg_runtime_dir, xdg_config_dirs, xdg_data_dirs,
    _path_from_env, _paths_from_env
)


class TestPathFromEnv:
    """Test _path_from_env helper function."""

    def test_path_from_env_with_absolute_path(self, monkeypatch, tmp_path):
        """Test _path_from_env returns env var when set to absolute path."""
        test_path = tmp_path / "custom"
        monkeypatch.setenv("TEST_VAR", str(test_path))
        result = _path_from_env("TEST_VAR", Path.home() / ".default")
        assert result == test_path

    def test_path_from_env_with_relative_path(self, monkeypatch):
        """Test _path_from_env returns default when env var is relative."""
        monkeypatch.setenv("TEST_VAR", "relative/path")
        default = Path.home() / ".default"
        result = _path_from_env("TEST_VAR", default)
        assert result == default

    def test_path_from_env_unset(self, monkeypatch):
        """Test _path_from_env returns default when env var unset."""
        monkeypatch.delenv("TEST_VAR", raising=False)
        default = Path.home() / ".default"
        result = _path_from_env("TEST_VAR", default)
        assert result == default

    def test_path_from_env_empty_string(self, monkeypatch):
        """Test _path_from_env returns default when env var is empty."""
        monkeypatch.setenv("TEST_VAR", "")
        default = Path.home() / ".default"
        result = _path_from_env("TEST_VAR", default)
        assert result == default


class TestPathsFromEnv:
    """Test _paths_from_env helper function."""

    def test_paths_from_env_with_colon_separated(self, monkeypatch, tmp_path):
        """Test _paths_from_env parses colon-separated paths."""
        path1 = tmp_path / "path1"
        path2 = tmp_path / "path2"
        monkeypatch.setenv("TEST_DIRS", f"{path1}:{path2}")
        result = _paths_from_env("TEST_DIRS", [Path("/default")])
        assert len(result) == 2
        assert path1 in result
        assert path2 in result

    def test_paths_from_env_filters_relative_paths(self, monkeypatch, tmp_path):
        """Test _paths_from_env ignores relative paths."""
        abs_path = tmp_path / "absolute"
        monkeypatch.setenv("TEST_DIRS", f"{abs_path}:relative/path")
        result = _paths_from_env("TEST_DIRS", [Path("/default")])
        assert len(result) == 1
        assert abs_path in result

    def test_paths_from_env_all_relative_uses_default(self, monkeypatch):
        """Test _paths_from_env returns default if all paths are relative."""
        monkeypatch.setenv("TEST_DIRS", "rel1:rel2:rel3")
        default = [Path("/default")]
        result = _paths_from_env("TEST_DIRS", default)
        assert result == default

    def test_paths_from_env_unset(self, monkeypatch):
        """Test _paths_from_env returns default when unset."""
        monkeypatch.delenv("TEST_DIRS", raising=False)
        default = [Path("/default1"), Path("/default2")]
        result = _paths_from_env("TEST_DIRS", default)
        assert result == default

    def test_paths_from_env_empty_string(self, monkeypatch):
        """Test _paths_from_env returns default when empty."""
        monkeypatch.setenv("TEST_DIRS", "")
        default = [Path("/default")]
        result = _paths_from_env("TEST_DIRS", default)
        assert result == default


class TestXdgCacheHome:
    """Test xdg_cache_home function."""

    def test_xdg_cache_home_default(self, monkeypatch):
        """Test xdg_cache_home returns default ~/.cache when unset."""
        monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
        result = xdg_cache_home()
        assert result == Path.home() / ".cache"

    def test_xdg_cache_home_from_env(self, monkeypatch, tmp_path):
        """Test xdg_cache_home uses XDG_CACHE_HOME when set."""
        cache_dir = tmp_path / "cache"
        monkeypatch.setenv("XDG_CACHE_HOME", str(cache_dir))
        result = xdg_cache_home()
        assert result == cache_dir


class TestXdgConfigHome:
    """Test xdg_config_home function."""

    def test_xdg_config_home_default(self, monkeypatch):
        """Test xdg_config_home returns default ~/.config when unset."""
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        result = xdg_config_home()
        assert result == Path.home() / ".config"

    def test_xdg_config_home_from_env(self, monkeypatch, tmp_path):
        """Test xdg_config_home uses XDG_CONFIG_HOME when set."""
        config_dir = tmp_path / "config"
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_dir))
        result = xdg_config_home()
        assert result == config_dir


class TestXdgDataHome:
    """Test xdg_data_home function."""

    def test_xdg_data_home_default(self, monkeypatch):
        """Test xdg_data_home returns default ~/.local/share when unset."""
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        result = xdg_data_home()
        assert result == Path.home() / ".local" / "share"

    def test_xdg_data_home_from_env(self, monkeypatch, tmp_path):
        """Test xdg_data_home uses XDG_DATA_HOME when set."""
        data_dir = tmp_path / "data"
        monkeypatch.setenv("XDG_DATA_HOME", str(data_dir))
        result = xdg_data_home()
        assert result == data_dir


class TestXdgStateHome:
    """Test xdg_state_home function."""

    def test_xdg_state_home_default(self, monkeypatch):
        """Test xdg_state_home returns default ~/.local/state when unset."""
        monkeypatch.delenv("XDG_STATE_HOME", raising=False)
        result = xdg_state_home()
        assert result == Path.home() / ".local" / "state"

    def test_xdg_state_home_from_env(self, monkeypatch, tmp_path):
        """Test xdg_state_home uses XDG_STATE_HOME when set."""
        state_dir = tmp_path / "state"
        monkeypatch.setenv("XDG_STATE_HOME", str(state_dir))
        result = xdg_state_home()
        assert result == state_dir


class TestXdgRuntimeDir:
    """Test xdg_runtime_dir function."""

    def test_xdg_runtime_dir_default(self, monkeypatch):
        """Test xdg_runtime_dir returns None when unset."""
        monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
        result = xdg_runtime_dir()
        assert result is None

    def test_xdg_runtime_dir_from_env(self, monkeypatch, tmp_path):
        """Test xdg_runtime_dir uses XDG_RUNTIME_DIR when set."""
        runtime_dir = tmp_path / "runtime"
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime_dir))
        result = xdg_runtime_dir()
        assert result == runtime_dir

    def test_xdg_runtime_dir_relative_path(self, monkeypatch):
        """Test xdg_runtime_dir returns None for relative paths."""
        monkeypatch.setenv("XDG_RUNTIME_DIR", "relative/path")
        result = xdg_runtime_dir()
        assert result is None


class TestXdgConfigDirs:
    """Test xdg_config_dirs function."""

    def test_xdg_config_dirs_default(self, monkeypatch):
        """Test xdg_config_dirs returns default [/etc/xdg] when unset."""
        monkeypatch.delenv("XDG_CONFIG_DIRS", raising=False)
        result = xdg_config_dirs()
        assert result == [Path("/etc/xdg")]

    def test_xdg_config_dirs_from_env(self, monkeypatch, tmp_path):
        """Test xdg_config_dirs uses XDG_CONFIG_DIRS when set."""
        dir1 = tmp_path / "config1"
        dir2 = tmp_path / "config2"
        monkeypatch.setenv("XDG_CONFIG_DIRS", f"{dir1}:{dir2}")
        result = xdg_config_dirs()
        assert dir1 in result
        assert dir2 in result


class TestXdgDataDirs:
    """Test xdg_data_dirs function."""

    def test_xdg_data_dirs_default(self, monkeypatch):
        """Test xdg_data_dirs returns default when unset."""
        monkeypatch.delenv("XDG_DATA_DIRS", raising=False)
        result = xdg_data_dirs()
        assert Path("/usr/local/share") in result
        assert Path("/usr/share") in result

    def test_xdg_data_dirs_from_env(self, monkeypatch, tmp_path):
        """Test xdg_data_dirs uses XDG_DATA_DIRS when set."""
        dir1 = tmp_path / "data1"
        dir2 = tmp_path / "data2"
        monkeypatch.setenv("XDG_DATA_DIRS", f"{dir1}:{dir2}")
        result = xdg_data_dirs()
        assert dir1 in result
        assert dir2 in result


class TestXdgReturnTypes:
    """Test return types of XDG functions."""

    def test_xdg_cache_home_returns_path(self, monkeypatch):
        """Test xdg_cache_home returns Path object."""
        monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
        result = xdg_cache_home()
        assert isinstance(result, Path)

    def test_xdg_config_dirs_returns_list(self, monkeypatch):
        """Test xdg_config_dirs returns list of Paths."""
        monkeypatch.delenv("XDG_CONFIG_DIRS", raising=False)
        result = xdg_config_dirs()
        assert isinstance(result, list)
        assert all(isinstance(p, Path) for p in result)

    def test_xdg_runtime_dir_returns_path_or_none(self, monkeypatch):
        """Test xdg_runtime_dir returns Path or None."""
        monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
        result = xdg_runtime_dir()
        assert result is None or isinstance(result, Path)
