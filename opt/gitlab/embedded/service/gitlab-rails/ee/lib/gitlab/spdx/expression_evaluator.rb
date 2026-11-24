# frozen_string_literal: true

module Gitlab
  module SPDX
    # Walks a Gitlab::SPDX::ExpressionParser node tree: `AND` matches only if every
    # operand matches, `OR` if any operand does. `evaluate_violation` walks the same
    # tree for a deny-list, where the dual holds: `AND` violates if any operand is
    # denied, `OR` violates only if every operand is denied. Includers implement
    # `evaluate_leaf(value, context)` and may override `evaluate_id`/`evaluate_literal`/
    # `evaluate_plus`/`evaluate_with`/`evaluate_fallback` when a node type needs more
    # than a plain leaf match; those hooks are polarity-agnostic and serve both walks.
    module ExpressionEvaluator
      COMPOUND_NODE_TYPES = %i[and or with plus].freeze

      private

      def evaluate(node, context = nil)
        dispatch(node, context, negate_combinators: false)
      end

      def evaluate_violation(node, context = nil)
        dispatch(node, context, negate_combinators: true)
      end

      def dispatch(node, context, negate_combinators:)
        case node.type
        when :and
          and_node_matches?(node, context, negate_combinators)
        when :or
          or_node_matches?(node, context, negate_combinators)
        when :with
          evaluate_with(node, context, negate_combinators: negate_combinators)
        when :id
          evaluate_id(node, context)
        when :literal
          evaluate_literal(node, context)
        when :plus
          evaluate_plus(node, context)
        else
          evaluate_fallback(node, context)
        end
      end

      # `AND`'s violation dual is `any?`, not `!all?` (a different, wrong formula:
      # see the class comment above).
      def and_node_matches?(node, context, negate_combinators)
        if negate_combinators
          node.children.any? { |child| dispatch(child, context, negate_combinators: negate_combinators) }
        else
          node.children.all? { |child| dispatch(child, context, negate_combinators: negate_combinators) }
        end
      end

      # `OR`'s violation dual is `all?`, not `!any?` (same trap as above, mirrored).
      def or_node_matches?(node, context, negate_combinators)
        if negate_combinators
          node.children.all? { |child| dispatch(child, context, negate_combinators: negate_combinators) }
        else
          node.children.any? { |child| dispatch(child, context, negate_combinators: negate_combinators) }
        end
      end

      # "base WITH exception" matches when the base license matches on its own,
      # or when the full expression is listed verbatim.
      def evaluate_with(node, context, negate_combinators: false)
        base_node, exception_node = node.children
        full_expression = "#{base_node.value} #{node.value} #{exception_node.value}"

        dispatch(base_node, context, negate_combinators: negate_combinators) || evaluate_leaf(full_expression, context)
      end

      def evaluate_id(node, context)
        evaluate_leaf(node.value, context)
      end

      def evaluate_literal(node, context)
        evaluate_leaf(node.value, context)
      end

      def evaluate_plus(node, context)
        evaluate_leaf(node.value, context)
      end

      def evaluate_fallback(node, context)
        evaluate_leaf(node.value.to_s, context)
      end
    end
  end
end
