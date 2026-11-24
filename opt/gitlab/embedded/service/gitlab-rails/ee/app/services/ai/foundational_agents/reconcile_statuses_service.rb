# frozen_string_literal: true

module Ai
  module FoundationalAgents
    # Makes a top-level group's foundational agent choices explicit before the switch starts gating
    # every agent (`duo_group_agent_readiness_settings`), so the group keeps running exactly the
    # agents it runs today. Idempotent: run it in the same change request as each rollout step, right
    # before the flag flips, so no group drifts into the old shape in between.
    class ReconcileStatusesService
      include Gitlab::Loggable

      BATCH_SIZE = 100

      # @param dry_run [Boolean] report the groups and agents without writing
      def initialize(dry_run: true)
        @dry_run = dry_run
      end

      # @return [ServiceResponse] payload `{ dry_run:, groups: [{ namespace_id:, agents_turned_off: }],
      #   skipped: [namespace_id], failures: [{ namespace_id:, error: }] }`, where `skipped` lists the groups
      #   whose switch a save turned on in the meantime; an error response when a group could not be written
      def execute
        groups = []
        skipped = []
        failures = []

        ::Ai::NamespaceSetting.with_foundational_agents_switch_off_and_agent_on
          .each_batch(of: BATCH_SIZE, column: :namespace_id) do |batch|
          batch.preload_namespace_and_foundational_agent_statuses.each do |setting|
            next if switch_gates_every_agent?(setting.namespace)

            result = reconcile(setting)
            result ? groups << result : skipped << setting.namespace_id
          rescue ActiveRecord::RecordInvalid, ActiveRecord::RecordNotUnique => e
            failures << { namespace_id: setting.namespace_id, error: e.message }
          end
        end

        payload = { dry_run: dry_run, groups: groups, skipped: skipped, failures: failures }
        return ServiceResponse.success(payload: payload) if failures.empty?

        ServiceResponse.error(message: "#{failures.size} group(s) could not be reconciled", payload: payload)
      end

      private

      attr_reader :dry_run

      # Where the flag already reached the group, the switch is off on purpose: it gates every agent there.
      def switch_gates_every_agent?(group)
        ::Feature.enabled?(:duo_group_agent_readiness_settings, group, type: :beta)
      end

      def reconcile(setting)
        group = setting.namespace
        references = dry_run ? missing_references(group) : write!(setting, group)
        return unless references

        log(group, references)

        { namespace_id: group.id, agents_turned_off: references }
      end

      def missing_references(group)
        listed_references(group) - group.foundational_agents_status_records.map(&:reference)
      end

      # The agents the settings page lists for the group: a save there rebuilds the records from the listed
      # agents only, so a record for a hidden agent would not survive it.
      def listed_references(group)
        ::Ai::FoundationalChatAgent.except_duo_chat_agent.select { |agent| agent.listed_for?(group) }.map(&:reference)
      end

      # Locks the settings row and re-reads it and the records inside the transaction: a save from the settings
      # page may have landed after the batch was loaded. A group whose switch it turned on stays as it wrote it
      # (nil); the explicit Off records land with the switch, so no agent is ever on by default in between.
      def write!(setting, group)
        ::ApplicationRecord.transaction do
          setting.lock!
          next if setting.foundational_agents_default_enabled

          group.foundational_agents_status_records.reset
          references = missing_references(group)

          references.each do |reference|
            group.foundational_agents_status_records.create!(reference: reference, enabled: false)
          end

          setting.update!(foundational_agents_default_enabled: true)

          references
        end
      end

      def log(group, references)
        verb = dry_run ? 'Would reconcile' : 'Reconciled'

        ::Gitlab::AppJsonLogger.info(
          build_structured_payload_labkit(
            Labkit::Fields::LOG_MESSAGE => "#{verb} foundational agent statuses with the switch",
            Labkit::Fields::GL_NAMESPACE_ID => group.id,
            agents_turned_off: references
          )
        )
      end
    end
  end
end
