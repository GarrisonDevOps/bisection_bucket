# frozen_string_literal: true

module MergeRequests
  module RiskConfidenceTier
    extend DeclarativeEnum

    key :tier
    name 'MergeRequestRiskConfidenceTier'
    description 'Confidence tier derived from a merge request risk confidence score.'

    define do
      low value: 0, description: N_('Low confidence.')
      medium value: 1, description: N_('Medium confidence.')
      high value: 2, description: N_('High confidence.')
      very_high value: 3, description: N_('Very high confidence.')
    end
  end
end
