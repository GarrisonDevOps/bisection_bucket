# frozen_string_literal: true

module VirtualRegistries
  class CreateAuditEventsService
    EVENT_MESSAGE = 'Marked cache entry for deletion'
    EVENT_NAMES = %w[
      virtual_registries_container_cache_remote_entry_deleted
      virtual_registries_packages_maven_cache_remote_entry_deleted
    ].freeze

    def initialize(entries:, event_name:, source: 'cleanup policy')
      @entries = entries
      @group = entries.first&.group
      @event_name = event_name
      @source = source
    end

    def execute
      return ServiceResponse.error(message: 'Invalid event name') unless EVENT_NAMES.include?(event_name.to_s)
      return ServiceResponse.error(message: 'No entries to audit') if entries.empty?

      ::Gitlab::Audit::Auditor.audit(initial_audit_context) do
        entries.each { |entry| send_event(entry) }
      end

      ServiceResponse.success
    rescue StandardError => e
      ServiceResponse.error(message: e.message)
    end

    private

    attr_reader :entries, :group, :event_name, :source

    def initial_audit_context
      {
        name: event_name,
        author: group.first_owner || ::Gitlab::Audit::UnauthenticatedAuthor.new,
        scope: group,
        target: ::Gitlab::Audit::NullTarget.new
      }
    end

    def send_event(entry)
      event = {
        target: entry,
        target_details: "#{entry.relative_path} marked for deletion by #{source}",
        message: EVENT_MESSAGE
      }

      entry.push_audit_event(event, after_commit: false)
    end
  end
end
