# frozen_string_literal: true

module Govern
  module PolicyStore
    # ActiveRecord implementation of the evaluation recorder port from
    # gems/gitlab-policy-store, backing it with the govern_policy_evaluations
    # and govern_policy_violations tables.
    #
    # Not an authorization boundary: permission checks belong to the calling
    # service layer.
    class ActiveRecordEvaluationRecorder < ::Gitlab::PolicyStore::Ports::EvaluationRecorder
      def record(attributes)
        normalized = recordable_attributes(attributes)
        evaluation = build_evaluation(normalized)

        save_record!(evaluation)

        # Keep the saved violations: reloading below resets the association cache,
        # and rereading them would cost a query without an ordering guarantee.
        violations = evaluation.violations.to_a

        # Postgres truncates the nanosecond timestamps Rails assigned, so a value object
        # built from the saved record would never equal one a later read returns.
        evaluation.reload # rubocop:disable Cop/ActiveRecordAssociationReload -- the record, not an association

        to_value_object(evaluation, violations)
      end

      private

      def build_evaluation(attributes)
        evaluation = ::Govern::PolicyEvaluation.new(
          organization_id: attributes[:organization_id],
          govern_policy_id: attributes[:policy_id],
          policy_version: attributes[:policy_version],
          trigger_type: attributes[:trigger_type],
          mode: attributes[:mode],
          verdict: attributes[:verdict],
          evaluated_at: attributes[:evaluated_at],
          project_id: attributes[:project_id],
          environment_id: attributes[:environment_id],
          user_id: attributes[:user_id]
        )

        (attributes[:violations] || []).each do |entry|
          evaluation.violations.build(
            organization_id: attributes[:organization_id],
            govern_policy_id: attributes[:policy_id],
            details: entry['details']
          )
        end

        evaluation
      end

      # Saving the evaluation saves its built violations in the same transaction,
      # so a rejected violation leaves no evaluation row behind.
      def save_record!(record)
        return if record.save

        messages = record.errors.full_messages +
          record.violations.flat_map { |violation| violation.errors.full_messages }

        raise ::Gitlab::PolicyStore::ValidationError, messages.uniq.to_sentence
      end

      def to_value_object(record, violations)
        ::Gitlab::PolicyStore::Evaluation.new(
          id: record.id,
          organization_id: record.organization_id,
          policy_id: record.govern_policy_id,
          policy_version: record.policy_version,
          trigger_type: record.trigger_type,
          mode: record.mode,
          verdict: record.verdict,
          evaluated_at: record.evaluated_at,
          project_id: record.project_id,
          environment_id: record.environment_id,
          user_id: record.user_id,
          violations: violations.map do |violation|
            ::Gitlab::PolicyStore::Violation.new(id: violation.id, details: violation.details.deep_dup)
          end
        )
      end
    end
  end
end
