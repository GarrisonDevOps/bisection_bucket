# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Reconcile
      module Input
        class ParamsExtractor
          # @param [Hash] context
          # @return [Hash]
          def self.extract(context)
            context => { original_params: Hash => original_params }

            original_params.symbolize_keys => {
              update_type: String => update_type,
              workspace_agent_infos: Array => workspace_agent_info_hashes_from_params,
            }

            # We extract the original string-keyed params, move them to the top level of context hash with descriptive
            # names, and deep-symbolize keys. The original_params will still remain in the context hash as well for
            # debugging purposes.

            context.merge(
              {
                update_type: update_type,
                workspace_agent_info_hashes_from_params: workspace_agent_info_hashes_from_params
              }.deep_symbolize_keys.to_h
            )
          end
        end
      end
    end
  end
end
