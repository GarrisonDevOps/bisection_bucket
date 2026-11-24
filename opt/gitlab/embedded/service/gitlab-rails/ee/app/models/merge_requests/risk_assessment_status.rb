# frozen_string_literal: true

module MergeRequests
  module RiskAssessmentStatus
    extend DeclarativeEnum

    key :status
    name 'MergeRequestRiskAssessmentStatus'
    description 'Status of a merge request risk assessment.'

    define do
      pending value: 0, description: N_('Waiting to be assessed.')
      queued value: 1, description: N_('Queued for (re)assessment.')
      complete value: 2, description: N_('Assessment has completed.')
      failed value: 3, description: N_('Assessment could not be completed.')
      scoring value: 4, description: N_('Assessment result received, waiting for its score.')
    end
  end
end
