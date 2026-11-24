# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # A session's flow_metadata_json. Rails records the flow a session starts with and
    # marks the record with CONSTRAINT_KEY; the first checkpoint, which the executor
    # relays, may only narrow its version. Without the marker it is the client's report.
    module FlowMetadata
      CONSTRAINT_KEY = 'flow_version_constraint'
      REVISION_KEY = 'resource_revision'

      def self.started(params)
        return unless params.is_a?(Hash)

        params = params.symbolize_keys
        return if params[:flow_config_id].blank? || params[:flow_version].blank?

        ::Gitlab::Json.dump({
          'flow_id' => params[:flow_config_id],
          'schema_version' => params[:flow_config_schema_version].presence,
          'flow_version' => params[:flow_version],
          CONSTRAINT_KEY => params[:flow_version]
        }.compact)
      end

      # What the first checkpoint stores, or nil to keep the stored value.
      def self.narrowed(stored_json, reported_json)
        stored = owned(stored_json)
        return reported_json unless stored

        reported = parse(reported_json)
        return unless reported && fits?(reported, stored)

        ::Gitlab::Json.dump(stored.merge('flow_version' => reported['flow_version']))
      end

      # Records the resource revision the session covers. Only a record Rails owns keeps it
      # past the first checkpoint, so anything else is returned unchanged.
      def self.with_revision(stored_json, revision)
        stored = owned(stored_json)
        return stored_json unless stored && revision.present?

        ::Gitlab::Json.dump(stored.merge(REVISION_KEY => revision))
      end

      def self.revision(stored_json)
        owned(stored_json)&.dig(REVISION_KEY)
      end

      # Start params for the session's next run, or nil when Rails recorded none.
      def self.pinned_params(stored_json)
        stored = owned(stored_json)
        return unless stored

        {
          flow_config_id: stored['flow_id'],
          flow_config_schema_version: stored['schema_version'],
          flow_version: stored['flow_version']
        }
      end

      def self.owned(json)
        metadata = parse(json)
        metadata if metadata && identity?(metadata) && metadata[CONSTRAINT_KEY].is_a?(String)
      end

      def self.parse(json)
        metadata = ::Gitlab::Json::SafeParser.parse(json) if json.present?
        metadata if metadata.is_a?(Hash)
      rescue JSON::ParserError
        nil
      end

      def self.identity?(metadata)
        metadata['flow_id'].is_a?(String) && metadata['flow_version'].is_a?(String) &&
          (metadata['schema_version'].nil? || metadata['schema_version'].is_a?(String))
      end

      def self.fits?(reported, stored)
        identity?(reported) &&
          reported['flow_id'] == stored['flow_id'] &&
          reported['schema_version'].presence == stored['schema_version'].presence &&
          FlowVersionConstraint.satisfied_by?(reported['flow_version'], stored[CONSTRAINT_KEY])
      end

      private_class_method :owned, :parse, :identity?, :fits?
    end
  end
end
