# frozen_string_literal: true

module AwardEmojis
  class AddService < AwardEmojis::BaseService
    include Gitlab::Utils::StrongMemoize

    def execute
      unless awardable.user_can_award?(current_user)
        return error('User cannot add emoji reactions to awardable', status: :forbidden)
      end

      unless awardable.emoji_awardable?
        return error('Awardable cannot add emoji reactions', status: :unprocessable_entity)
      end

      if award_emoji_limit_reached?
        return error(_('This item has the maximum number of emoji reactions.'), status: :unprocessable_entity)
      end

      award = awardable.award_emoji.create(name: name, user: current_user)

      if award.persisted?
        after_create(award)
        remove_other_skin_tones
        success(award: award)
      else
        error(award.errors.full_messages, award: award)
      end
    end

    private

    # A user holds at most one tone of an emoji per awardable, whichever path adds the reaction.
    # Runs only after the add succeeded, so a failed add keeps the user's existing reaction.
    def remove_other_skin_tones
      return unless Feature.enabled?(:emoji_skin_tone_preference, current_user)

      names = other_skin_tone_names
      return if names.empty?

      AwardEmojisFinder.new(awardable, name: names, awarded_by: current_user).execute.each do |award|
        DestroyService.new(awardable, award.name, current_user).execute
      end
    end

    # A skin tone swap replaces the user's existing tone, so it skips the per-user cap.
    # It can still add a name, so the names cap applies.
    def award_emoji_limit_reached?
      (awardable.award_emoji_user_limit_reached?(current_user) && !skin_tone_swap?) ||
        awardable.award_emoji_names_limit_reached?(name)
    end

    def skin_tone_swap?
      Feature.enabled?(:emoji_skin_tone_preference, current_user) &&
        awardable.awarded_emoji?(other_skin_tone_names, current_user)
    end

    def other_skin_tone_names
      skin_tones = Gitlab::Emoji::SkinTones

      [skin_tones.base_name(name), *skin_tones.variants_for(name)] - [name]
    end

    def after_create(award)
      TodoService.new.new_award_emoji(todoable, current_user) if todoable

      execute_hooks(award, 'award')
    end

    def todoable
      strong_memoize(:todoable) do
        case awardable
        when DiscussionNote
          # Only update todos associated with the discussion if note is part of a thread
          awardable.to_discussion
        when Note
          # We don't create todos for personal snippet comments for now
          awardable.noteable unless awardable.for_personal_snippet?
        when MergeRequest, Issue
          awardable
        else
          # No todos for all other awardables
          nil
        end
      end
    end
  end
end

AwardEmojis::AddService.prepend_mod_with('AwardEmojis::AddService')
