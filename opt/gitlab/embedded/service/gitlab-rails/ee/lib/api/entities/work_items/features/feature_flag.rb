# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module Features
        class FeatureFlag < Grape::Entity
          expose :id,
            documentation: { type: 'Integer', example: 1, desc: 'ID of the feature flag, unique across the instance.' }
          expose :name, documentation: { type: 'String', example: 'my_feature_flag', desc: 'Name of the feature flag.' }
          expose :active,
            documentation: { type: 'Boolean', example: true, desc: 'Whether the feature flag is active.' }
          expose :path,
            documentation: {
              type: 'String', example: '/group/project/-/feature_flags/1/edit',
              desc: 'Relative path to the edit page of the feature flag.'
            }
          expose :reference,
            documentation: {
              type: 'String', example: '[feature_flag:1]',
              desc: 'Reference to the feature flag, using its internal ID. Includes the project path when the ' \
                "feature flag's project differs from the work item's namespace."
            } do |flag, options|
            flag.to_reference(options[:reference_from])
          end
        end
      end
    end
  end
end
