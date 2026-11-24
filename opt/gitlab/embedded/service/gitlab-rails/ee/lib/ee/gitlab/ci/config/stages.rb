# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module Config
        module Stages
          extend ActiveSupport::Concern
          include ::Gitlab::Utils::StrongMemoize

          RESERVED_POLICY_PRE = '.pipeline-policy-pre'
          RESERVED_POLICY_POST = '.pipeline-policy-post'
          RESERVED = [RESERVED_POLICY_PRE, RESERVED_POLICY_POST].freeze

          class_methods do
            def wrap_with_reserved_stages(stages)
              stages = stages.to_a - RESERVED
              stages.unshift RESERVED_POLICY_PRE
              stages.push RESERVED_POLICY_POST

              stages
            end
          end

          def inject_reserved_stages!
            # If stages are not declared in config, we use the default stages to inject the reserved stages into.
            stages_to_wrap = stages.presence || ::Gitlab::Ci::Config::Entry::Stages.default

            config[:stages] = wrap_with_reserved_stages(stages_to_wrap)
            config
          end

          delegate :wrap_with_reserved_stages, to: :class
        end
      end
    end
  end
end
