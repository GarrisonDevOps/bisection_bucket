# frozen_string_literal: true

module Ai
  module Compliance
    module Anthropic
      class Session < ApplicationRecord
        self.table_name = 'ai_compliance_anthropic_sessions'

        belongs_to :namespace, class_name: '::Group', optional: false
        belongs_to :anthropic_integration, class_name: '::Ai::Compliance::Anthropic::Integration',
          optional: false
        belongs_to :ai_governance_session, class_name: '::Ai::Governance::Session', optional: false

        validates :ai_governance_session_id, uniqueness: true
        validates :session_xid, presence: true, length: { maximum: 255 }
        validates :message_watermark, length: { maximum: 255 }
        validate :namespace_matches_integration
        validate :namespace_matches_governance_session

        populate_sharding_key :namespace_id, source: :anthropic_integration, field: :namespace_id

        def self.find_for(ai_governance_session)
          find_by(ai_governance_session_id: ai_governance_session.id)
        end

        # A transcript walk creates the row the first time it walks a session. A concurrent walk can
        # win the insert; read its row back.
        def self.find_or_create_for!(anthropic_integration:, ai_governance_session:, session_xid:)
          find_by(ai_governance_session_id: ai_governance_session.id) ||
            create!(
              anthropic_integration: anthropic_integration,
              ai_governance_session: ai_governance_session,
              session_xid: session_xid
            )
        rescue ActiveRecord::RecordNotUnique
          find_by!(ai_governance_session_id: ai_governance_session.id)
        rescue ActiveRecord::RecordInvalid => e
          raise unless e.record.errors.of_kind?(:ai_governance_session_id, :taken)

          find_by!(ai_governance_session_id: ai_governance_session.id)
        end

        def start_walk!
          update!(walk_started_at: Time.current)
        end

        # A nil watermark keeps the stored one. Given `walk_started_at`, commits only while that walk
        # is still the latest, so an older overlapping walk cannot move the watermark backwards.
        # update_all skips timestamps, so updated_at is set here: the taper reads it as the finish.
        # @return [Boolean] whether the commit applied
        def commit_walk!(watermark, walk_started_at: nil)
          attributes = { walk_started_at: nil, updated_at: Time.current }
          attributes[:message_watermark] = watermark if watermark

          scope = self.class.id_in(id)
          scope = scope.where(walk_started_at: walk_started_at) if walk_started_at

          scope.update_all(attributes) == 1
        end

        private

        # @return [void]
        def namespace_matches_integration
          return if anthropic_integration.nil? || namespace_id == anthropic_integration.namespace_id

          errors.add(:namespace, _('must match the Anthropic Compliance integration namespace'))

          nil
        end

        # @return [void]
        def namespace_matches_governance_session
          return if ai_governance_session.nil? || namespace_id == ai_governance_session.namespace_id

          errors.add(:namespace, _('must match the AI governance session namespace'))

          nil
        end
      end
    end
  end
end
