# frozen_string_literal: true

module Gitlab
  module Duo
    module CodeReview
      module Availability
        def available?(container)
          availability_for(container).available?
        end

        def automatic_review_available?(container)
          availability_for(container).automatic_review_available?
        end

        def depth_settings_available?(container)
          availability_for(container).depth_settings_available?
        end

        def default_depth(container)
          availability_for(container).default_depth
        end

        def decisions_settings_available?(container)
          availability_for(container).decisions_settings_available?
        end

        def approval_counts_available?(container)
          availability_for(container, only: ::Project).approval_counts_available?
        end

        private

        def availability_for(container, only: nil)
          if only && Array.wrap(only).none? { |klass| container.is_a?(klass) }
            raise ArgumentError, "Unsupported container type: #{container.class}"
          end

          case container
          when ::Project
            Project.new(container)
          when ::Namespace
            Namespace.new(container)
          when ::ApplicationSetting
            Instance.new(container)
          else
            raise ArgumentError, "Unsupported container type: #{container.class}"
          end
        end
      end
    end
  end
end
