# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module Pipeline
        module Chain
          module Config
            module Content
              extend ::Gitlab::Utils::Override

              private

              override :pipeline_config_params
              def pipeline_config_params
                # rubocop: disable Gitlab/ModuleWithInstanceVariables -- Adding necessary parameter
                super.merge(scan_profile_context: @command.scan_profile_context)
                # rubocop: enable Gitlab/ModuleWithInstanceVariables
              end
            end
          end
        end
      end
    end
  end
end
