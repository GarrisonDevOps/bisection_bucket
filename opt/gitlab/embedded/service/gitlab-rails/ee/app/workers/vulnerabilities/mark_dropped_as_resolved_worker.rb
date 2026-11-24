# frozen_string_literal: true

module Vulnerabilities
  class MarkDroppedAsResolvedWorker
    include ApplicationWorker

    VULNERABILITY_IDENTIFIERS_BATCH_SIZE = 250

    data_consistency :delayed
    idempotent!
    deduplicate :until_executing, including_scheduled: true

    feature_category :static_application_security_testing

    loggable_arguments 1

    def perform(project_id, dropped_identifier_ids)
      project = Project.find_by_id(project_id)
      return unless project

      bot_user = Users::Internal.in_organization(project.organization).security_bot
      resolvable_vulnerabilities(dropped_identifier_ids) do |vulnerabilities|
        next unless vulnerabilities.present?

        # rubocop:disable CodeReuse/ActiveRecord -- `update_all` changes the result of the query, so grab the ids first to do the system notes
        vulnerability_ids = vulnerabilities.pluck(:id)
        # rubocop:enable CodeReuse/ActiveRecord

        current_time = Time.zone.now

        state_transitions = build_state_transitions(vulnerabilities, current_time, bot_user)

        ::Vulnerability.feature_flagged_transaction_for(nil) do
          vulnerabilities.update_all(
            resolved_by_id: bot_user.id,
            resolved_at: current_time,
            updated_at: current_time,
            state: :resolved)

          Vulnerabilities::StateTransition.bulk_insert!(state_transitions)
        end

        vulnerability_relation = Vulnerability.by_ids(vulnerability_ids)

        ::Vulnerabilities::BulkEsOperationService.new(vulnerability_relation).execute

        create_system_notes(vulnerability_relation, bot_user)
      end
    end

    private

    def resolvable_vulnerabilities(identifier_ids)
      # rubocop:disable CodeReuse/ActiveRecord -- unusual order, pluck and where calls is very specific to this query
      order = Gitlab::Pagination::Keyset::Order.build([
        Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
          attribute_name: 'vulnerability_id',
          order_expression: Vulnerabilities::Finding.arel_table[:vulnerability_id].asc,
          nullable: :not_nullable
        )
      ])

      identifier_ids.each do |identifier_id|
        scope = Vulnerabilities::Finding.where(primary_identifier_id: identifier_id).order(order)

        Gitlab::Pagination::Keyset::Iterator.new(scope: scope)
                                            .each_batch(of: VULNERABILITY_IDENTIFIERS_BATCH_SIZE) do |records|
          vulnerability_ids = records.map(&:vulnerability_id)

          yield ::Vulnerability.id_in(vulnerability_ids).with_states(:detected).with_resolution(true)
        end
      end
      # rubocop:enable CodeReuse/ActiveRecord
    end

    def build_state_transitions(vulnerabilities, current_time, bot_user)
      vulnerabilities.find_each.map do |vulnerability|
        build_state_transition_for(vulnerability, current_time, bot_user)
      end
    end

    def create_system_notes(vulnerabilities, bot_user)
      vulnerabilities.find_each do |vulnerability|
        create_system_note(vulnerability, bot_user)
      end
    end

    def create_system_note(vulnerability, bot_user)
      SystemNoteService.change_vulnerability_state(
        vulnerability,
        bot_user,
        resolution_comment
      )
    end

    def build_state_transition_for(vulnerability, current_time, bot_user)
      ::Vulnerabilities::StateTransition.new(
        vulnerability: vulnerability,
        vulnerability_occurrence_id: vulnerability.finding_id,
        from_state: vulnerability.state,
        to_state: :resolved,
        author_id: bot_user.id,
        comment: resolution_comment,
        created_at: current_time,
        updated_at: current_time
      )
    end

    def resolution_comment
      # rubocop:disable Gitlab/DocumentationLinks/HardcodedUrl
      _("This vulnerability was automatically resolved because its vulnerability type was disabled in this project " \
        "or removed from GitLab's default ruleset. " \
        "For details about SAST rule changes, " \
        "see https://docs.gitlab.com/ee/user/application_security/sast/rules#important-rule-changes.")
      # rubocop:enable Gitlab/DocumentationLinks/HardcodedUrl
    end
  end
end
