# frozen_string_literal: true

module Gitlab
  module Ai
    module DapFactory
      # A validated `.gitlab-dap-factory.yml`. Build one with Validator, never directly from YAML.
      class Configuration
        PATH = '.gitlab-dap-factory.yml'

        # Fixed and ordered. A work item only ever moves forward through these, so the order decides
        # which stage runs next.
        STAGES = %w[triage plan build verify review ship].freeze

        # The other keys of the status block. The flows of the factory read them, Sync does not.
        STATUS_EXTRA_KEYS = %w[complete declined blocked by_work_item_type].freeze
        STATUS_KEYS = (STAGES + STATUS_EXTRA_KEYS).freeze

        AUTOMATED = 'automated'
        MANUAL = 'manual'
        MODES = [AUTOMATED, MANUAL].freeze

        # Review's flow starts when the reviewer requests changes on a merge request, not on a status change.
        MERGE_REQUEST_DRIVEN_STAGES = %w[review].freeze

        # The Software Factory marker is set when a work item gets a workplan. These stages run before
        # it has one, so they start for every work item with their status.
        INTAKE_STAGES = %w[triage plan].freeze

        Stage = Data.define(:key, :skipped, :status, :start_mode, :exit_mode, :flow, :mark_merge_requests_ready) do
          def self.skipped(key)
            new(key: key, skipped: true, status: nil, start_mode: nil, exit_mode: nil, flow: nil,
              mark_merge_requests_ready: false)
          end

          def skipped?
            skipped
          end

          def automated_start?
            !skipped? && start_mode == AUTOMATED
          end

          def automated_exit?
            !skipped? && exit_mode == AUTOMATED
          end

          def merge_request_driven?
            MERGE_REQUEST_DRIVEN_STAGES.include?(key)
          end

          def intake?
            INTAKE_STAGES.include?(key)
          end

          def triggered?
            automated_start? && flow.present?
          end

          def status_triggered?
            triggered? && !merge_request_driven?
          end
        end

        attr_reader :factory_name, :stages, :review

        def initialize(factory_name:, stages:, review:)
          @factory_name = factory_name
          @stages = stages
          @review = review
        end

        def stage(key)
          stages.find { |stage| stage.key == key.to_s }
        end

        def next_stage_after(key)
          index = STAGES.index(key.to_s)
          return unless index

          stages.drop(index + 1).find { |stage| !stage.skipped? }
        end

        def triggered_stages
          stages.select(&:triggered?)
        end

        # The status a trigger sets when its flow succeeds, or nil when a person moves the work item on.
        def status_on_finish_for(stage)
          return unless stage.automated_exit?

          next_stage_after(stage.key)&.status
        end
      end
    end
  end
end
