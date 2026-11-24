# frozen_string_literal: true

module SecretsManagement
  module Secrets
    module ListNeedingRotationServiceHelpers
      def execute
        result = super(include_rotation_info: true)

        return result unless result.success?

        secrets = filter_secrets_needing_rotation(result.payload[:secrets])
        secrets = order_by_rotation_urgency(secrets)

        ServiceResponse.success(payload: { secrets: secrets })
      end

      private

      def filter_secrets_needing_rotation(secrets)
        secrets.select do |secret|
          secret.rotation_info&.needs_attention?
        end
      end

      def order_by_rotation_urgency(secrets)
        # Sort secrets needing rotation by urgency priority:
        # 1. OVERDUE secrets first (priority 0), then APPROACHING secrets (priority 1)
        # 2. Within OVERDUE: Sort by created_at (ascending) - older secret versions are more urgent
        #    because created_at represents when the current secret value was last rotated.
        #    A secret created 3 months ago is more stale than one created 1 week ago.
        # 3. Within APPROACHING: Sort by next_reminder_at (ascending) - secrets due sooner are more urgent
        #
        # Note: When a secret is updated, a new rotation info record is created with a fresh
        # created_at timestamp. This means created_at effectively tracks "how long has this secret
        # value existed without being rotated" for overdue secrets.
        secrets.sort_by do |secret|
          rotation_info = secret.rotation_info
          if rotation_info.status == SecretsManagement::BaseSecretRotationInfo::STATUSES[:overdue]
            [0, rotation_info.created_at] # Oldest version = most urgent
          else
            [1, rotation_info.next_reminder_at] # Earliest due = most urgent
          end
        end
      end
    end
  end
end
