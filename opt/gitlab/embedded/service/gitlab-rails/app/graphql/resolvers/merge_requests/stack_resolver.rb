# frozen_string_literal: true

module Resolvers
  module MergeRequests
    class StackResolver < BaseResolver
      prepend ::MergeRequests::LookAheadPreloads

      # Room to list every member of one full stack together with its stack.
      MAX_STACK_NODES = ::MergeRequests::StackFinder::MAX_STACK_SIZE.then { |size| size * (size + 1) }

      type [::Types::MergeRequestType], null: true

      alias_method :merge_request, :object

      def resolve_with_lookahead
        check_stack_nodes_limit!
        stack = apply_lookahead(::MergeRequests::StackFinder.new(current_user, merge_request).execute).to_a
        count_stack_nodes(stack.size)
        check_stack_nodes_limit!

        stack
      end

      private

      # The limit counts on the context, which the queries of a multiplex share, and counts a
      # field that finds no stack as one, because it still runs the finder. The log counts the
      # merge requests returned, on the per-query namespace.
      def count_stack_nodes(size)
        context[:stack_nodes] = context[:stack_nodes].to_i + [size, 1].max

        log_fields = context.namespace(:gl_logging)[:log_fields] ||= {}
        log_fields[:graphql_stack_nodes] = log_fields.fetch(:graphql_stack_nodes, 0) + size
      end

      def check_stack_nodes_limit!
        return if context[:stack_nodes].to_i <= MAX_STACK_NODES

        raise ::Gitlab::Graphql::Errors::LimitError,
          "\"stack\" can return at most #{MAX_STACK_NODES} merge requests in one request, " \
            "counting at least one for each field."
      end
    end
  end
end
