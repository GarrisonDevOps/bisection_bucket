# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module Pipeline
        module Chain
          module Config
            module Process
              extend ::Gitlab::Utils::Override

              private

              override :yaml_processor_opts
              def yaml_processor_opts
                super.merge(
                  pipeline_policy_context: command.pipeline_policy_context,
                  scan_profile_context: command.scan_profile_context
                )
              end
            end
          end
        end
      end
    end
  end
end
