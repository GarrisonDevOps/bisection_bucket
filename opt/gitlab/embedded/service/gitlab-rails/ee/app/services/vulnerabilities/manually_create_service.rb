# frozen_string_literal: true

module Vulnerabilities
  class ManuallyCreateService < CreateServiceBase
    include Gitlab::Allowable

    METADATA_VERSION = "manual:1.0"
    CONFIRMED_MESSAGE = "confirmed_at can only be set when state is confirmed"
    RESOLVED_MESSAGE = "resolved_at can only be set when state is resolved"
    DISMISSED_MESSAGE = "dismissed_at can only be set when state is dismissed"
    TIMESTAMP_MESSAGES = {
      confirmed_at: CONFIRMED_MESSAGE,
      resolved_at: RESOLVED_MESSAGE,
      dismissed_at: DISMISSED_MESSAGE
    }.freeze
    STATES_AND_TIMESTAMPS_MAPPING = {
      "detected" => nil,
      "confirmed" => :confirmed_at,
      "resolved" => :resolved_at,
      "dismissed" => :dismissed_at
    }.freeze

    def execute
      raise Gitlab::Access::AccessDeniedError unless authorized?

      timestamps_dont_match_state_message = match_state_fields_with_state
      return error(message: timestamps_dont_match_state_message) if timestamps_dont_match_state_message

      ensure_timestamps!

      vulnerability = initialize_vulnerability(@params[:vulnerability])
      identifiers = initialize_identifiers(@params[:vulnerability][:identifiers])
      scanner = initialize_scanner(@params[:vulnerability][:scanner])
      finding = initialize_finding(
        vulnerability: vulnerability,
        identifiers: identifiers,
        scanner: scanner,
        description: @params[:vulnerability][:description],
        solution: @params[:vulnerability][:solution]
      )

      unless validate_quota!
        return error(
          message: "Vulnerability count has passed its limit. Vulnerabilities cannot be created."
        )
      end

      response = Vulnerability.feature_flagged_transaction_for(project) do
        finding.save!
        vulnerability.vulnerability_finding = finding
        vulnerability.save!
        finding.update!(vulnerability_id: vulnerability.id)

        Vulnerabilities::Reads::UpsertService.new(
          vulnerability,
          {
            vulnerability_occurrence_id: finding.id,
            traversal_ids: project.namespace.traversal_ids,
            security_project_tracked_context_id: finding.security_project_tracked_context_id
          },
          projects: @project,
          update_all_vulnerabilities: true,
          findings: [finding]
        ).execute

        update_security_statistics!

        Vulnerabilities::StatisticsUpdateService.update_for(vulnerability)
        Vulnerabilities::Findings::RiskScoreCalculationService.calculate_for(vulnerability)

        ServiceResponse.success(payload: { vulnerability: vulnerability })
      end

      mark_project_as_vulnerable!

      process_archival_and_traversal_ids_changes if response.success?

      response
    rescue Security::ProjectTrackedContexts::BusyError => e
      error(message: e.message)
    rescue ActiveRecord::RecordNotUnique => e
      Gitlab::ErrorTracking.log_exception(e, project_id: project.id)
      error(message: "Vulnerability with those details already exists")
    rescue ActiveRecord::RecordInvalid => e
      error(message: e.message, errors: e.record.errors.full_messages)
    end

    private

    def error(message:, errors: [])
      ServiceResponse.error(
        message: message,
        payload: { errors: [message] + errors }
      )
    end

    def location_fingerprint(_location_hash)
      uuid = SecureRandom.uuid

      Digest::SHA1.hexdigest("manually-created-vulnerability-#{uuid}")
    end

    def metadata_version
      METADATA_VERSION
    end

    # rubocop: disable CodeReuse/ActiveRecord
    def initialize_scanner(scanner_hash)
      # In database Vulnerabilities::Scanner#id is autoincrementing primary key
      # In the GraphQL mutation mutation arguments we want to respect the security scanner schema:
      # https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/blob/master/src/security-report-format.json#L339
      # So the id provided to the mutation is actually external_id in our database
      Vulnerabilities::Scanner.find_or_initialize_by(external_id: scanner_hash[:id], project_id: @project.id) do |s|
        s.name = scanner_hash[:name]
        s.vendor = scanner_hash.dig(:vendor, :name).to_s
      end
    end
    # rubocop: enable CodeReuse/ActiveRecord

    def state
      @params.dig(:vulnerability, :state)
    end

    # A state may only carry its own timestamp. `detected` has none, so it may carry no timestamp.
    def match_state_fields_with_state
      return unless STATES_AND_TIMESTAMPS_MAPPING.key?(state)

      own_timestamp = STATES_AND_TIMESTAMPS_MAPPING[state]

      TIMESTAMP_MESSAGES.each do |timestamp, message|
        next if timestamp == own_timestamp

        return message if exists_in_vulnerability_params?(timestamp)
      end

      nil
    end

    def exists_in_vulnerability_params?(column_name)
      @params.dig(:vulnerability, column_name.to_sym).present?
    end

    def ensure_timestamps!
      timestamp = STATES_AND_TIMESTAMPS_MAPPING[state]

      return unless timestamp

      @params[:vulnerability][timestamp] = @params[:vulnerability][timestamp].presence || Time.zone.now
    end
  end
end
