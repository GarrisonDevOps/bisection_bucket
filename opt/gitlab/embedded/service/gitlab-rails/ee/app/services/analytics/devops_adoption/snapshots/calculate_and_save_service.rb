# frozen_string_literal: true

module Analytics
  module DevopsAdoption
    module Snapshots
      class CalculateAndSaveService
        attr_reader :enabled_namespace, :range_end

        def initialize(enabled_namespace:, range_end:)
          @enabled_namespace = enabled_namespace
          @range_end = range_end
        end

        def execute
          save_snapshot
        rescue ActiveRecord::RecordNotUnique
          # A concurrent job inserted this month's row between the lookup and the save;
          # keep the booleans it recorded and update it instead of rescanning the subtree.
          @snapshot = nil
          Snapshot::BOOLEAN_METRICS.each { |metric| calculated_data[metric] ||= snapshot[metric] }
          save_snapshot
        end

        def snapshot
          @snapshot ||= enabled_namespace.snapshots.for_month(range_end).first_or_initialize
        end

        def calculated_data
          @calculated_data ||= SnapshotCalculator.new(enabled_namespace: enabled_namespace, range_end: range_end, snapshot: snapshot).calculate
        end

        private

        def save_snapshot
          UpdateService.new(snapshot: snapshot, params: calculated_data).execute
        end
      end
    end
  end
end
