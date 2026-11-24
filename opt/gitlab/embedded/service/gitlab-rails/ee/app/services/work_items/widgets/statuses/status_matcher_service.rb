# frozen_string_literal: true

module WorkItems
  module Widgets
    module Statuses
      class StatusMatcherService
        def initialize(old_status, new_lifecycle)
          @old_status = old_status
          @new_lifecycle = new_lifecycle
        end

        def find_fallback
          return unless old_status && new_lifecycle

          find_name_and_state_match ||
            find_category_match ||
            find_default_for_state
        end

        private

        attr_reader :old_status, :new_lifecycle

        def find_name_and_state_match
          new_lifecycle.statuses.find do |status|
            status.name.casecmp(old_status.name) == 0 && status.state == old_status.state
          end
        end

        def find_category_match
          new_lifecycle.statuses.find { |status| status.category.to_s == old_status.category.to_s }
        end

        def find_default_for_state
          case old_status.state
          when :open
            new_lifecycle.default_open_status
          when :closed
            new_lifecycle.default_closed_status
          end
        end
      end
    end
  end
end
