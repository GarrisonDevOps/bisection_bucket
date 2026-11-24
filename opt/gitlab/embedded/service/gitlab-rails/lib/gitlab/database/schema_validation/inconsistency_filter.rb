# frozen_string_literal: true

module Gitlab
  module Database
    module SchemaValidation
      # Drops expected inconsistencies, such as the lock-writes triggers that
      # LockWritesManager adds and structure.sql never has.
      class InconsistencyFilter
        IGNORED_TRIGGERS = ['gitlab_schema_write_trigger_for_'].freeze

        # Inconsistency#type returns the validator class name.
        TRIGGER_VALIDATORS = [
          Gitlab::Schema::Validation::Validators::ExtraTriggers,
          Gitlab::Schema::Validation::Validators::MissingTriggers
        ].map(&:name).freeze

        def initialize(triggers = IGNORED_TRIGGERS)
          @triggers = triggers
        end

        def to_proc
          proc do |inconsistency|
            inconsistency unless ignored?(inconsistency)
          end
        end

        private

        attr_reader :triggers

        def ignored?(inconsistency)
          TRIGGER_VALIDATORS.include?(inconsistency.type) && ignored_trigger?(inconsistency.object_name)
        end

        def ignored_trigger?(name)
          triggers.any? { |ignored_object| name.to_s.include?(ignored_object) }
        end
      end
    end
  end
end
