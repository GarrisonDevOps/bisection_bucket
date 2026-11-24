# frozen_string_literal: true

module EE
  module Gitlab
    module GithubImport
      module Stage
        module ImportLfsObjectsWorker
          extend ::Gitlab::Utils::Override

          private

          override :next_stage
          def next_stage(project)
            return super unless import_settings(project).enabled?(:continuous_sync)

            'continuous_sync'
          end
        end
      end
    end
  end
end
