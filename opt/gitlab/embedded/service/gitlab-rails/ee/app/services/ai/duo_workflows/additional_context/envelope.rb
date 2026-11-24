# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module AdditionalContext
      # `version` is omitted for flow-owned supplements that predate versioning
      # (see FoundationalFlowContextBuilder).
      module Envelope
        def self.wrap(category:, fields:, version: nil)
          envelope = {
            "Category" => category.to_s,
            "Content" => ::Gitlab::Json.dump(fields)
          }
          envelope["metadata"] = { "version" => version } if version

          envelope
        end

        # The shape the StartWorkflowRequest proto decodes, used by the Workhorse path: lowercase
        # keys and metadata as a JSON string. protojson silently drops keys it does not know, and
        # DWS fails the request when metadata is missing, so unversioned envelopes send "{}".
        def self.to_wire(envelope)
          {
            "category" => envelope["Category"],
            "content" => envelope["Content"],
            "metadata" => ::Gitlab::Json.dump(envelope["metadata"] || {})
          }
        end
      end
    end
  end
end
