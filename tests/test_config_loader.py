#!/usr/bin/env python3
"""Tests for config_loader module."""

import unittest
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.config_loader import Rule, Condition, extract_frontmatter


class TestHookFieldParsing(unittest.TestCase):
    """Tests for the hook field (pre/post) parsing."""

    def test_hook_pre_normalized_from_uppercase(self):
        """hook: 'PRE' should normalize to 'pre'"""
        rule = Rule.from_dict(
            {'name': 'test', 'event': 'bash', 'pattern': 'x', 'hook': 'PRE'},
            'message'
        )
        self.assertEqual(rule.hook, 'pre')

    def test_hook_post_normalized_from_uppercase(self):
        """hook: 'POST' should normalize to 'post'"""
        rule = Rule.from_dict(
            {'name': 'test', 'event': 'bash', 'pattern': 'x', 'hook': 'Post'},
            'message'
        )
        self.assertEqual(rule.hook, 'post')

    def test_hook_invalid_value_becomes_none(self):
        """hook: 'invalid' should become None (match both phases)"""
        rule = Rule.from_dict(
            {'name': 'test', 'event': 'bash', 'pattern': 'x', 'hook': 'bogus'},
            'message'
        )
        self.assertIsNone(rule.hook)

    def test_hook_not_specified_is_none(self):
        """Missing hook field should be None"""
        rule = Rule.from_dict(
            {'name': 'test', 'event': 'bash', 'pattern': 'x'},
            'message'
        )
        self.assertIsNone(rule.hook)


class TestMessageUserParsing(unittest.TestCase):
    """Tests for message_user field parsing."""

    def test_message_user_preserved(self):
        """message_user from frontmatter should be accessible"""
        rule = Rule.from_dict(
            {'name': 'test', 'event': 'bash', 'pattern': 'x', 'message_user': 'alert'},
            'body content'
        )
        self.assertEqual(rule.message_user, 'alert')
        self.assertEqual(rule.message, 'body content')

    def test_message_user_not_specified_is_none(self):
        """Missing message_user should be None"""
        rule = Rule.from_dict(
            {'name': 'test', 'event': 'bash', 'pattern': 'x'},
            'body only'
        )
        self.assertIsNone(rule.message_user)
        self.assertEqual(rule.message, 'body only')


class TestPatternToCondition(unittest.TestCase):
    """Tests for simple pattern to condition conversion."""

    def test_bash_pattern_creates_command_condition(self):
        """event: bash with pattern should create condition on 'command' field"""
        rule = Rule.from_dict(
            {'name': 'test', 'event': 'bash', 'pattern': 'rm -rf'},
            ''
        )
        self.assertEqual(len(rule.conditions), 1)
        self.assertEqual(rule.conditions[0].field, 'command')
        self.assertEqual(rule.conditions[0].operator, 'regex_match')
        self.assertEqual(rule.conditions[0].pattern, 'rm -rf')

    def test_file_pattern_creates_new_text_condition(self):
        """event: file with pattern should create condition on 'new_text' field"""
        rule = Rule.from_dict(
            {'name': 'test', 'event': 'file', 'pattern': 'console\\.log'},
            ''
        )
        self.assertEqual(rule.conditions[0].field, 'new_text')

    def test_explicit_conditions_override_pattern(self):
        """Explicit conditions list should be used instead of pattern"""
        rule = Rule.from_dict({
            'name': 'test',
            'event': 'bash',
            'pattern': 'ignored',
            'conditions': [
                {'field': 'command', 'operator': 'contains', 'pattern': 'used'}
            ]
        }, '')
        self.assertEqual(len(rule.conditions), 1)
        self.assertEqual(rule.conditions[0].pattern, 'used')
        self.assertEqual(rule.conditions[0].operator, 'contains')


class TestFrontmatterExtraction(unittest.TestCase):
    """Tests for YAML frontmatter extraction."""

    def test_extracts_frontmatter_and_body(self):
        """Should separate YAML frontmatter from markdown body"""
        content = """---
name: test-rule
enabled: true
event: bash
---

This is the body.
"""
        frontmatter, body = extract_frontmatter(content)
        self.assertEqual(frontmatter['name'], 'test-rule')
        self.assertEqual(frontmatter['enabled'], True)
        self.assertIn('This is the body', body)

    def test_handles_no_frontmatter(self):
        """Content without frontmatter should return empty dict"""
        content = "Just a body without frontmatter"
        frontmatter, body = extract_frontmatter(content)
        self.assertEqual(frontmatter, {})


if __name__ == '__main__':
    unittest.main()
