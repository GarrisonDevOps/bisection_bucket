# frozen_string_literal: true

module Security
  # Shared by the two validity display state resolvers.
  module ResolvesValidityDisplayState
    PENDING_VERIFICATION_STATE = 'pending_verification'

    private

    # id_attribute keys the batch as well as indexing the rows, so the two
    # resolvers' finding ids never share one queue.
    def resolve_validity_display_state(finding, id_attribute:)
      display_state = ::Security::SecretDetection::ValiditySupport.display_state(
        token_type: finding.token_type,
        source: ::Security::SecretDetection::Scanners.target_for_finding(finding)
      )
      return display_state unless display_state.nil?

      BatchLoader::GraphQL.for(finding.id).batch(key: id_attribute) do |finding_ids, loader|
        statuses = yield(finding_ids).index_by(&id_attribute)

        finding_ids.each do |finding_id|
          loader.call(finding_id, statuses[finding_id]&.status || PENDING_VERIFICATION_STATE)
        end
      end
    end
  end
end
