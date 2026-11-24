# frozen_string_literal: true

module EE
  module WorkItems
    module LookAheadPreloads
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      private

      override :preloads
      def preloads
        super.merge(
          promoted_to_epic_url: :work_item_transition
        )
      end

      override :widget_preloads
      def widget_preloads
        super.merge(
          [:widgets, :escalation_policy] => { incident_management_issuable_escalation_status: :policy },
          [:widgets, :feature_flags] => { feature_flags: :project },
          [:widgets, :iteration] => { iteration: :group },
          [:widgets, :progress] => :progress,
          [:widgets, :status] => { current_status: :custom_status },
          [:widgets, :test_reports] => :test_reports,
          [:widgets, :verification_status] => { requirement: :recent_test_reports },
          [:widgets, :rolled_up_weight] => :weights_source,
          [:widgets, :rolled_up_completed_weight] => :weights_source,
          [:widgets, :custom_field_values] => custom_field_value_preloads
        )
      end

      override :feature_preloads
      def feature_preloads
        super.merge(
          [:features, :development, :feature_flags] => { feature_flags: :project },
          [:features, :escalation_policy, :escalation_policy] => {
            incident_management_issuable_escalation_status: :policy
          },
          [:features, :iteration, :iteration] => { iteration: :group },
          [:features, :progress, :progress] => :progress,
          [:features, :status, :status] => { current_status: :custom_status },
          [:features, :test_reports, :test_reports] => :test_reports,
          [:features, :verification_status, :verification_status] => { requirement: :recent_test_reports },
          [:features, :weight, :rolled_up_weight] => :weights_source,
          [:features, :weight, :rolled_up_completed_weight] => :weights_source,
          [:features, :custom_fields, :custom_field_values] => custom_field_value_preloads
        )
      end

      def custom_field_value_preloads
        [
          :text_field_values,
          :number_field_values,
          :date_field_values,
          { select_field_values: :custom_field_select_option }
        ]
      end

      def unconditional_includes
        [
          *super,
          :sync_object,
          :namespace
        ]
      end
    end
  end
end
