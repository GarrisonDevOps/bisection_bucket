# frozen_string_literal: true

module EE
  module API
    module AwardEmoji
      extend ActiveSupport::Concern

      prepended do
        helpers do
          # Keyword options, because Grape 3.x drops a positionally passed options hash.
          def present(objects, **options)
            if awardable.is_a?(::Epic)
              super(objects, **options.merge(
                with: ::API::Entities::LegacyEpicAwardEmoji,
                epic: awardable
              ))
            else
              super
            end
          end
        end
      end
    end
  end
end
