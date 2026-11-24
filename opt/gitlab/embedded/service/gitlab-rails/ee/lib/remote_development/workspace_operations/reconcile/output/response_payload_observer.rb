# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Reconcile
      module Output
        class ResponsePayloadObserver
          # @param [Hash] context
          # @return [void]
          def self.observe(context)
            context => {
              agent: agent, # Skip type checking so we can use fast_spec_helper in the unit test spec
              update_type: String => update_type,
              response_payload: {
                workspace_rails_infos: Array => workspace_rails_infos,
                settings: {
                  full_reconciliation_interval_seconds: Integer => full_reconciliation_interval_seconds,
                  partial_reconciliation_interval_seconds: Integer => partial_reconciliation_interval_seconds
                },
              },
              observability_for_rails_infos: Hash => observability_for_rails_infos,
              logger: logger, # Skip type checking to avoid coupling to Rails logger
            }

            # NOTE: Do _NOT_ include any values in this logging which:
            #  - Contain potentially sensitive data, such as the config_to_apply value.
            #    You can set the GITLAB_DEBUG_WORKSPACES_OBSERVE_CONFIG_TO_APPLY ENV variable to log config_to_apply.
            #    See documentation at ../../README.md#debugging for more information.
            #  - Contain a large amount of raw data which would unnecessarily fill up the logs.
            logger.debug(
              message: 'Returning verified response_payload',
              agent_id: agent.id,
              update_type: update_type,
              response_payload: {
                workspace_rails_info_count: workspace_rails_infos.length,
                workspace_rails_infos: workspace_rails_infos.map do |rails_info|
                  if ENV["GITLAB_DEBUG_WORKSPACES_OBSERVE_CONFIG_TO_APPLY"]
                    rails_info
                  else
                    rails_info.reject { |k, _| k == :config_to_apply }
                  end
                end,
                settings: {
                  full_reconciliation_interval_seconds: full_reconciliation_interval_seconds,
                  partial_reconciliation_interval_seconds: partial_reconciliation_interval_seconds
                }
              },
              observability_for_rails_infos: observability_for_rails_infos
            )

            nil
          end
        end
      end
    end
  end
end
