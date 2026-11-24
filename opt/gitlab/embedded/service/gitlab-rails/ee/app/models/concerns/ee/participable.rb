# frozen_string_literal: true

module EE
  module Participable
    extend ::Gitlab::Utils::Override

    override :filter_by_ability
    def filter_by_ability(participants)
      return super unless is_a?(Epic)

      Ability.users_that_can_read_group(participants.to_a, group)
    end

    override :can_read_participable?
    def can_read_participable?(participant)
      return super unless is_a?(Epic)

      Ability.allowed?(participant, :read_group, group)
    end
  end
end
