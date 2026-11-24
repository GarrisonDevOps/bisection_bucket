# frozen_string_literal: true

module Gitlab
  module Graphql
    module Tracers
      # Emits audit events for CI/CD variable values accessed by a query.
      #
      # Variable values are resolved per node, so accesses are accumulated in
      # Gitlab::Ci::Variables::AccessCollector during execution and audited here,
      # once per query and variable owner.
      module CiVariableAuditTracer
        AUDIT_EVENT_NAME = 'variable_viewed_graphql'

        # Auditing from `ensure` records values read by a query that later
        # failed too: they were already decrypted in process, so the access is
        # worth recording even when the client received an error.
        def execute_multiplex(multiplex:)
          super
        ensure
          multiplex.queries.each { |query| audit_variable_access(query) }
        end

        private

        def audit_variable_access(query)
          collector = ::Gitlab::Ci::Variables::AccessCollector.recorded_in(query.context)
          return if collector.nil? || collector.empty?

          author = query.context[:current_user]
          return unless author

          collector.each do |access|
            audit_variable_access_for(author, access)
          rescue StandardError => e
            # Auditing must neither fail an otherwise successful query nor drop
            # the events for the remaining owners.
            ::Gitlab::ErrorTracking.track_exception(
              e, scope_type: access.scope.class.name, scope_id: access.scope.id
            )
          end
        end

        def audit_variable_access_for(author, access)
          accessed_keys = access.accessed_keys.to_a.sort
          hidden_keys = access.hidden_keys.to_a.sort

          ::Gitlab::Audit::Auditor.audit(
            name: AUDIT_EVENT_NAME,
            author: author,
            scope: access.scope,
            target: access.scope,
            # A hidden-only access has no keys to report. Nil falls back to the
            # target's own details; an empty string would not.
            target_details: accessed_keys.join(', ').presence,
            message: 'CI/CD variables accessed with GraphQL',
            additional_details: {
              api_type: 'graphql',
              accessed_keys: accessed_keys,
              hidden_keys: hidden_keys,
              truncated: access.truncated?
            }
          )
        end
      end
    end
  end
end
