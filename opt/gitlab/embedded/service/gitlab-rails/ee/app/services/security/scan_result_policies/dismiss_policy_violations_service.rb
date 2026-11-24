# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class DismissPolicyViolationsService
      include Gitlab::Utils::StrongMemoize

      def initialize(merge_request, current_user:, params: {})
        @merge_request = merge_request
        @current_user = current_user
        @params = params
      end

      def execute
        return ServiceResponse.error(message: "No warn mode policies are found.") if warn_mode_policies.blank?

        violations_by_policy = group_violations_by_policy
        dismissal_attributes = build_dismissal_attributes(violations_by_policy)

        return ServiceResponse.success if dismissal_attributes.empty?

        upsert_policy_dismissals(dismissal_attributes)
        trigger_merge_request_update_subscriptions

        ServiceResponse.success
      end

      private

      attr_reader :merge_request, :current_user, :params

      def warn_mode_policies
        Security::Policy.id_in(params[:security_policy_ids]).with_warn_mode
      end
      strong_memoize_attr :warn_mode_policies

      def group_violations_by_policy
        merge_request
          .scan_result_policy_violations
          .for_security_policies(warn_mode_policies)
          .group_by_security_policy_id
      end

      def build_dismissal_attributes(violations_by_policy)
        violations_by_policy.each_with_object([]) do |(policy_id, violations), attrs|
          finding_uuids = collect_finding_uuids(violations)
          licenses = collect_licenses(violations)

          attrs << dismissal_attributes_for(policy_id, finding_uuids, licenses)
        end
      end

      def collect_finding_uuids(violations)
        violations.flat_map(&:finding_uuids).uniq
      end

      def collect_licenses(violations)
        license_violations(violations).reduce({}) do |result, licenses|
          result.merge(licenses) { |_license_name, existing, new| existing | new }
        end
      end

      def license_violations(violations)
        violations.map(&:licenses).compact_blank
      end

      def dismissal_attributes_for(policy_id, finding_uuids, licenses)
        {
          security_findings_uuids: finding_uuids,
          licenses: licenses,
          security_policy_id: policy_id,
          merge_request_id: merge_request.id,
          project_id: merge_request.project_id,
          user_id: current_user.id,
          dismissal_types: params[:dismissal_types],
          comment: params[:comment]
        }
      end

      def upsert_policy_dismissals(attributes)
        Security::PolicyDismissal.upsert_all(attributes, unique_by: %i[security_policy_id merge_request_id])
      end

      def trigger_merge_request_update_subscriptions
        GraphqlTriggers.merge_request_approval_state_updated(merge_request)
        GraphqlTriggers.merge_request_merge_status_updated(merge_request)
      end
    end
  end
end
