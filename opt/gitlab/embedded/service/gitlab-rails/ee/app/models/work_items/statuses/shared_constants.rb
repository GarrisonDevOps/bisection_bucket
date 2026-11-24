# frozen_string_literal: true

module WorkItems
  module Statuses
    module SharedConstants
      # Note: We rely on categories for ordering work items by status.
      # If new categories are added, their placement will affect sort order.
      CATEGORIES = {
        triage: 1,
        to_do: 2,
        in_progress: 3,
        done: 4,
        canceled: 5
      }.freeze

      CATEGORY_ICONS = {
        triage: 'status-neutral',
        to_do: 'status-waiting',
        in_progress: 'status-running',
        done: 'status-success',
        canceled: 'status-cancelled'
      }.freeze

      DEFAULT_STATUS_CATEGORIES = {
        default_open_status: [:triage, :to_do, :in_progress],
        default_closed_status: [:done, :canceled],
        default_duplicate_status: [:done, :canceled]
      }.freeze

      CATEGORIES_STATE = {
        open: [:triage, :to_do, :in_progress],
        closed: [:done, :canceled]
      }.freeze
    end
  end
end
