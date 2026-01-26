#!/usr/bin/env python3
"""Tests for rule_engine module."""

import unittest
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.config_loader import Rule, Condition
from core.rule_engine import RuleEngine


def make_rule(name='test', event='bash', action='warn', hook=None,
              message='test message', message_user=None, pattern='echo'):
    """Helper to create test rules with sensible defaults."""
    return Rule(
        name=name,
        enabled=True,
        event=event,
        pattern=pattern,
        conditions=[Condition(field='command', operator='contains', pattern=pattern)],
        action=action,
        hook=hook,
        message=message,
        message_user=message_user
    )


def make_input(hook_event='PreToolUse', tool='Bash', command='echo hello'):
    """Helper to create test input data."""
    return {
        'hook_event_name': hook_event,
        'tool_name': tool,
        'tool_input': {'command': command}
    }


class TestAdditionalContextBugFix(unittest.TestCase):
    """Tests for the critical additionalContext bug fix.

    Original bug: Claude couldn't see hook messages because only
    systemMessage was set, not additionalContext.
    """

    def test_response_includes_additional_context(self):
        """additionalContext must be present - this was the original bug"""
        engine = RuleEngine()
        rule = make_rule()

        result = engine.evaluate_rules([rule], make_input())

        self.assertIn('hookSpecificOutput', result)
        self.assertIn('additionalContext', result['hookSpecificOutput'])

    def test_additional_context_contains_message(self):
        """additionalContext should contain the rule's message"""
        engine = RuleEngine()
        rule = make_rule(message='detailed guidance for Claude')

        result = engine.evaluate_rules([rule], make_input())

        self.assertIn('detailed guidance for Claude',
                      result['hookSpecificOutput']['additionalContext'])


class TestHookPhaseFiltering(unittest.TestCase):
    """Tests for hook: pre/post filtering."""

    def test_hook_pre_skips_posttooluse(self):
        """rule with hook: pre should NOT match PostToolUse events"""
        engine = RuleEngine()
        rule = make_rule(hook='pre')

        result = engine.evaluate_rules([rule], make_input(hook_event='PostToolUse'))

        self.assertEqual(result, {})

    def test_hook_pre_matches_pretooluse(self):
        """rule with hook: pre should match PreToolUse events"""
        engine = RuleEngine()
        rule = make_rule(hook='pre')

        result = engine.evaluate_rules([rule], make_input(hook_event='PreToolUse'))

        self.assertIn('hookSpecificOutput', result)

    def test_hook_post_skips_pretooluse(self):
        """rule with hook: post should NOT match PreToolUse events"""
        engine = RuleEngine()
        rule = make_rule(hook='post')

        result = engine.evaluate_rules([rule], make_input(hook_event='PreToolUse'))

        self.assertEqual(result, {})

    def test_hook_post_matches_posttooluse(self):
        """rule with hook: post should match PostToolUse events"""
        engine = RuleEngine()
        rule = make_rule(hook='post')

        result = engine.evaluate_rules([rule], make_input(hook_event='PostToolUse'))

        self.assertIn('hookSpecificOutput', result)

    def test_hook_none_matches_pretooluse(self):
        """rule without hook field should match PreToolUse"""
        engine = RuleEngine()
        rule = make_rule(hook=None)

        result = engine.evaluate_rules([rule], make_input(hook_event='PreToolUse'))

        self.assertIn('hookSpecificOutput', result)

    def test_hook_none_matches_posttooluse(self):
        """rule without hook field should match PostToolUse"""
        engine = RuleEngine()
        rule = make_rule(hook=None)

        result = engine.evaluate_rules([rule], make_input(hook_event='PostToolUse'))

        self.assertIn('hookSpecificOutput', result)


class TestMessageSeparation(unittest.TestCase):
    """Tests for message_user feature - separate user/Claude messages."""

    def test_message_user_goes_to_system_message(self):
        """message_user should appear in systemMessage"""
        engine = RuleEngine()
        rule = make_rule(message='detailed', message_user='short alert')

        result = engine.evaluate_rules([rule], make_input())

        self.assertIn('short alert', result['systemMessage'])

    def test_body_goes_to_additional_context(self):
        """message (body) should appear in additionalContext"""
        engine = RuleEngine()
        rule = make_rule(message='detailed guidance', message_user='short')

        result = engine.evaluate_rules([rule], make_input())

        self.assertIn('detailed guidance',
                      result['hookSpecificOutput']['additionalContext'])

    def test_message_user_not_in_additional_context(self):
        """message_user should NOT leak into additionalContext"""
        engine = RuleEngine()
        rule = make_rule(message='for claude only', message_user='user alert')

        result = engine.evaluate_rules([rule], make_input())

        self.assertNotIn('user alert',
                         result['hookSpecificOutput']['additionalContext'])

    def test_no_message_user_means_empty_system_message(self):
        """Without message_user, systemMessage should be empty"""
        engine = RuleEngine()
        rule = make_rule(message='claude sees this', message_user=None)

        result = engine.evaluate_rules([rule], make_input())

        self.assertEqual(result['systemMessage'], '')

    def test_no_message_user_body_still_in_additional_context(self):
        """Without message_user, body still goes to additionalContext"""
        engine = RuleEngine()
        rule = make_rule(message='guidance for claude', message_user=None)

        result = engine.evaluate_rules([rule], make_input())

        self.assertIn('guidance for claude',
                      result['hookSpecificOutput']['additionalContext'])


class TestBlockVsWarn(unittest.TestCase):
    """Tests for action: block vs warn behavior."""

    def test_block_sets_permission_decision_deny(self):
        """action: block must set permissionDecision: deny"""
        engine = RuleEngine()
        rule = make_rule(action='block')

        result = engine.evaluate_rules([rule], make_input())

        self.assertEqual(
            result['hookSpecificOutput'].get('permissionDecision'),
            'deny'
        )

    def test_warn_does_not_deny(self):
        """action: warn should not set permissionDecision to deny"""
        engine = RuleEngine()
        rule = make_rule(action='warn')

        result = engine.evaluate_rules([rule], make_input())

        self.assertNotEqual(
            result['hookSpecificOutput'].get('permissionDecision'),
            'deny'
        )


class TestEdgeCases(unittest.TestCase):
    """Tests for edge cases and boundaries."""

    def test_no_matching_rules_returns_empty_dict(self):
        """When no rules match, return {} to allow operation"""
        engine = RuleEngine()
        rule = make_rule(pattern='nomatch')

        result = engine.evaluate_rules([rule], make_input(command='different'))

        self.assertEqual(result, {})

    def test_multiple_matching_rules_combines_messages(self):
        """Multiple matches should combine all messages"""
        engine = RuleEngine()
        rule1 = make_rule(name='rule1', message='first message')
        rule2 = make_rule(name='rule2', message='second message')

        result = engine.evaluate_rules([rule1, rule2], make_input())

        additional = result['hookSpecificOutput']['additionalContext']
        self.assertIn('first message', additional)
        self.assertIn('second message', additional)

    def test_empty_rules_list_returns_empty_dict(self):
        """Empty rules list should return {} (no-op)"""
        engine = RuleEngine()

        result = engine.evaluate_rules([], make_input())

        self.assertEqual(result, {})

    def test_disabled_rule_does_not_match(self):
        """Rules with enabled=False should not match"""
        engine = RuleEngine()
        rule = Rule(
            name='disabled',
            enabled=False,
            event='bash',
            conditions=[Condition('command', 'contains', 'echo')],
            action='warn',
            message='should not see this'
        )

        result = engine.evaluate_rules([rule], make_input())

        self.assertEqual(result, {})


if __name__ == '__main__':
    unittest.main()
