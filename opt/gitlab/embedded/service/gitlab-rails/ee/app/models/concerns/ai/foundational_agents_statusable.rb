# frozen_string_literal: true

module Ai
  module FoundationalAgentsStatusable
    extend ActiveSupport::Concern

    included do
      def foundational_agents_statuses=(values)
        return unless values

        self.class.transaction do
          foundational_agents_status_records.delete_all(:delete_all)

          values.each do |status|
            persistable = status.with_indifferent_access.slice(:reference, :enabled)
            # A missing record means the agent uses the default, so nil has nothing to persist.
            next if persistable[:enabled].nil?

            record = foundational_agents_status_records.build(persistable)

            errors.add(:foundational_agents_statuses, record.errors.full_messages.join(', ')) unless record.save
          end

          raise ActiveRecord::Rollback if errors.any?
        end
      end

      def foundational_agents_statuses
        statuses = foundational_agents_status_records.index_by(&:reference)

        ::Ai::FoundationalChatAgent.except_duo_chat_agent.map do |agent|
          status_record = statuses[agent.reference]

          {
            reference: agent.reference,
            name: agent.name,
            description: agent.description,
            enabled: status_record&.enabled
          }
        end
      end

      def enabled_foundational_agents
        statuses = foundational_agents_status_records.index_by(&:reference)
        resolver = ::Ai::FoundationalAgents::EnabledResolver.for(self)

        ::Ai::FoundationalChatAgent.all.select do |agent|
          agent.duo_chat? || resolver.enabled?(statuses[agent.reference]&.enabled)
        end
      end

      def foundational_agent_enabled?(reference)
        return true if ::Ai::FoundationalChatAgent::CHAT_REFERENCES.include?(reference)

        record = foundational_agents_status_records.find_by(reference: reference)

        ::Ai::FoundationalAgents::EnabledResolver.for(self).enabled?(record&.enabled)
      end
    end
  end
end
