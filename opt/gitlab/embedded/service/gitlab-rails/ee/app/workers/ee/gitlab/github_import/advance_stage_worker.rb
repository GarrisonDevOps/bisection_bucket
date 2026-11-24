# frozen_string_literal: true

module EE
  module Gitlab
    module GithubImport
      module AdvanceStageWorker
        extend ::Gitlab::Utils::Override

        private

        override :next_stage_worker
        def next_stage_worker(next_stage)
          return ::Gitlab::GithubImport::Stage::EnableContinuousSyncWorker if next_stage.to_s == 'continuous_sync'

          super
        end
      end
    end
  end
end
