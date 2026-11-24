# frozen_string_literal: true

module EE
  module Members
    module InviteService
      extend ::Gitlab::Utils::Override

      override :process_result
      def process_result(member)
        if member.errors.added?(:base, :queued)
          member_id = invited_object(member)
          queued_users[member_id] = member.errors.delete(:base, :queued).first
        end

        super(member)
      end
    end
  end
end
