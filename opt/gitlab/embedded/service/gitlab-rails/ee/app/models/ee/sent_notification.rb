# frozen_string_literal: true

module EE
  module SentNotification # rubocop:disable Gitlab/BoundedContexts -- EE module for existing model
    extend ::Gitlab::Utils::Override

    private

    override :namespace_id_from_noteable
    def namespace_id_from_noteable
      case noteable
      when Epic
        noteable.group_id
      else
        super
      end
    end
  end
end
