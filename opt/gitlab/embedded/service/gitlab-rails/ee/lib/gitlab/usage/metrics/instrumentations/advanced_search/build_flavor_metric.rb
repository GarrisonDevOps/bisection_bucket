# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        module AdvancedSearch
          class BuildFlavorMetric < GenericMetric
            value do
              if ::Gitlab::CurrentSettings.elasticsearch_indexing?
                ::Search::Elastic::Helper.default.server_info[:build_flavor] || 'unknown'
              else
                'NA'
              end
            end
          end
        end
      end
    end
  end
end
