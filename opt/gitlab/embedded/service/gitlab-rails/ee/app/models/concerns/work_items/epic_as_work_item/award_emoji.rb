# frozen_string_literal: true

module WorkItems
  module EpicAsWorkItem
    module AwardEmoji
      extend ActiveSupport::Concern

      included do
        has_many :award_emoji, -> { includes(:user).order(:id) },
          as: :awardable, inverse_of: :awardable do
          include DelegatedAssociationMethods

          def scope
            proxy_association.owner.work_item&.award_emoji || ::AwardEmoji.none
          end
        end
      end
    end
  end
end
